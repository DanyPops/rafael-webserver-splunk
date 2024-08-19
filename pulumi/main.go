package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/pulumi/pulumi-azure-native-sdk/compute/v2"
	"github.com/pulumi/pulumi-azure-native-sdk/network/v2"
	"github.com/pulumi/pulumi-azure-native-sdk/resources/v2"
	"github.com/pulumi/pulumi-random/sdk/v4/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
	"golang.org/x/crypto/ssh"
)

func MakeSSHKeyPair(publicKeyPath, privateKeyPath string) error {
	// Check if Key exists
	_, err := os.Stat(privateKeyPath)

	// No error means the key exists, do nothing
	if err == nil {
		return nil
	}

	// If error isn't "doesn't exist" exit
	if !os.IsNotExist(err) {
		return err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	defer privateKeyFile.Close()
	if err != nil {
		return err
	}

	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(pub), 0655)
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Import configuration settings
		cfg := config.New(ctx, "")
		namePrefix, err := cfg.Try("namePrefix")
		if err != nil {
			namePrefix = "rafael"
		}

		vmSize, err := cfg.Try("vmSize")
		if err != nil {
			vmSize = "Standard_A1_v2"
		}

		linuxImage, err := cfg.Try("linuxImage")
		if err != nil {
			linuxImage = "Debian:debian-11:11:latest"
		}

		adminUsername, err := cfg.Try("adminUsername")
		if err != nil {
			adminUsername = "rafael"
		}

		servicePort, err := cfg.Try("servicePort")
		if err != nil {
			servicePort = "80"
		}

		sshKeyPath, err := cfg.Try("hostVmSshKeyPath")
		if err != nil {
			sshKeyPath = os.Getenv("HOME") + "/.ssh/az-rafael-host-vm"
		}
		sshPubKeyPath := sshKeyPath + ".pub"

    // Cloud-Init is a Linux VM configuration developed by the OpenStack project
		cloudInit, err := os.ReadFile("./cloud-init.yaml")
    if err != nil {
      return err
    }

		// Check if SSH key exists, create if required
		if err := MakeSSHKeyPair(sshPubKeyPath, sshKeyPath); err != nil {
			return fmt.Errorf("failed to create SSH key pair %s: %v", sshKeyPath, err)
		}

		// Read the SSH key pair
		sshKeyBytes, err := os.ReadFile(sshKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read SSH private key '%s': %v", sshKeyPath, err)
		}
		sshKey := pulumi.ToSecret(string(sshKeyBytes))

		sshPubKeyBytes, err := os.ReadFile(sshPubKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read SSH public key '%s': %v", sshKeyPath, err)
		}
		sshPubKey := pulumi.String(string(sshPubKeyBytes))

		linuxImageArgs := strings.Split(linuxImage, ":")
		linuxImagePublisher := linuxImageArgs[0]
		linuxImageOffer := linuxImageArgs[1]
		linuxImageSku := linuxImageArgs[2]
		linuxImageVersion := linuxImageArgs[3]

		webserverVmName := fmt.Sprintf("%s-webserver", namePrefix)
		// adVmName := fmt.Sprintf("%s-active-directory", namePrefix)

		// Create a resource group
		rGroup, err := resources.NewResourceGroup(ctx, fmt.Sprintf("%s-rg", namePrefix), nil)
		if err != nil {
			return err
		}

		// Create SSH Key resources
		sshKeyAz, err := compute.NewSshPublicKey(ctx, fmt.Sprintf("%s-host-vm-key", namePrefix), &compute.SshPublicKeyArgs{
			ResourceGroupName: rGroup.Name,
			PublicKey:         sshPubKey,
		})
		if err != nil {
			return err
		}

		// Create a virtual network
		vnet, err := network.NewVirtualNetwork(ctx, fmt.Sprintf("%s-network", namePrefix), &network.VirtualNetworkArgs{
			ResourceGroupName: rGroup.Name,
			AddressSpace: network.AddressSpaceArgs{
				AddressPrefixes: pulumi.ToStringArray([]string{
					"10.0.0.0/16",
				}),
			},
		})
		if err != nil {
			return err
		}

		subnet, err := network.NewSubnet(ctx, fmt.Sprintf("%s-subnet", namePrefix), &network.SubnetArgs{
			ResourceGroupName:  rGroup.Name,
			VirtualNetworkName: vnet.Name,
			AddressPrefix:      pulumi.String("10.0.1.0/24"),
		})
		if err != nil {
			return err
		}

		// Use a random string to give the VM a unique DNS name
		domainLabelSuffix, err := random.NewRandomString(ctx, "domain-label", &random.RandomStringArgs{
			Length:  pulumi.Int(8),
			Upper:   pulumi.Bool(false),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return err
		}

		domainLabel := domainLabelSuffix.Result.ApplyT(func(result string) string {
			return fmt.Sprintf("%s-%s", namePrefix, result)
		}).(pulumi.StringOutput)

		// Create a public IP address for the webserver
		webserverPubIp, err := network.NewPublicIPAddress(ctx, "webserver-public-ip", &network.PublicIPAddressArgs{
			ResourceGroupName:        rGroup.Name,
			PublicIPAllocationMethod: pulumi.StringPtr("Dynamic"),
			DnsSettings: network.PublicIPAddressDnsSettingsArgs{
				DomainNameLabel: domainLabel,
			},
		})
		if err != nil {
			return err
		}

		// Create a security group allowing inbound access over ports 80 (for HTTP) and 22 (for SSH)
		securityGroup, err := network.NewNetworkSecurityGroup(ctx, "security-group", &network.NetworkSecurityGroupArgs{
			ResourceGroupName: rGroup.Name,
			SecurityRules: network.SecurityRuleTypeArray{
				network.SecurityRuleTypeArgs{
					Name:                     pulumi.StringPtr(fmt.Sprintf("%s-securityrule", namePrefix)),
					Priority:                 pulumi.Int(1000),
					Direction:                pulumi.String("Inbound"),
					Access:                   pulumi.String("Allow"),
					Protocol:                 pulumi.String("Tcp"),
					SourcePortRange:          pulumi.StringPtr("*"),
					SourceAddressPrefix:      pulumi.StringPtr("*"),
					DestinationAddressPrefix: pulumi.StringPtr("*"),
					DestinationPortRanges: pulumi.ToStringArray([]string{
						servicePort,
						"22",
					}),
				},
			},
		})
		if err != nil {
			return err
		}

		// Create a network interface with the virtual network, IP address, and security group
		webserverNic, err := network.NewNetworkInterface(ctx, "webserver-nic", &network.NetworkInterfaceArgs{
			ResourceGroupName: rGroup.Name,
			NetworkSecurityGroup: &network.NetworkSecurityGroupTypeArgs{
				Id: securityGroup.ID(),
			},
			IpConfigurations: network.NetworkInterfaceIPConfigurationArray{
				&network.NetworkInterfaceIPConfigurationArgs{
					Name:                      pulumi.String(fmt.Sprintf("%s-ipconfiguration", namePrefix)),
					PrivateIPAllocationMethod: pulumi.String("Dynamic"),
					Subnet: &network.SubnetTypeArgs{
						Id: subnet.ID(),
					},
					PublicIPAddress: &network.PublicIPAddressTypeArgs{
						Id: webserverPubIp.ID(),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		// Create the virtual machine
		webserverVm, err := compute.NewVirtualMachine(ctx, "webserver-vm", &compute.VirtualMachineArgs{
			ResourceGroupName: rGroup.Name,
			NetworkProfile: &compute.NetworkProfileArgs{
				NetworkInterfaces: compute.NetworkInterfaceReferenceArray{
					&compute.NetworkInterfaceReferenceArgs{
						Id:      webserverNic.ID(),
						Primary: pulumi.Bool(true),
					},
				},
			},
			HardwareProfile: &compute.HardwareProfileArgs{
				VmSize: pulumi.String(vmSize),
			},
			OsProfile: &compute.OSProfileArgs{
				ComputerName:  pulumi.String(webserverVmName),
				AdminUsername: pulumi.String(adminUsername),
				CustomData:    pulumi.String(base64.StdEncoding.EncodeToString(cloudInit)),
				LinuxConfiguration: &compute.LinuxConfigurationArgs{
					DisablePasswordAuthentication: pulumi.Bool(true),
					Ssh: &compute.SshConfigurationArgs{
						PublicKeys: compute.SshPublicKeyTypeArray{
							&compute.SshPublicKeyTypeArgs{
								KeyData: sshKeyAz.PublicKey,
								Path:    pulumi.String(fmt.Sprintf("/home/%v/.ssh/authorized_keys", adminUsername)),
							},
						},
					},
				},
			},
			StorageProfile: &compute.StorageProfileArgs{
				OsDisk: &compute.OSDiskArgs{
					Name:         pulumi.String(fmt.Sprintf("%v-osdisk", namePrefix)),
					CreateOption: pulumi.String("FromImage"),
				},
				ImageReference: &compute.ImageReferenceArgs{
					Publisher: pulumi.String(linuxImagePublisher),
					Offer:     pulumi.String(linuxImageOffer),
					Sku:       pulumi.String(linuxImageSku),
					Version:   pulumi.String(linuxImageVersion),
				},
			},
		})
		if err != nil {
			return err
		}

		// Once the machine is created, fetch its IP address and DNS hostname
		address := webserverVm.ID().ApplyT(func(_ pulumi.ID) network.LookupPublicIPAddressResultOutput {
			return network.LookupPublicIPAddressOutput(ctx, network.LookupPublicIPAddressOutputArgs{
				ResourceGroupName:   rGroup.Name,
				PublicIpAddressName: webserverPubIp.Name,
			})
		})

		// Export the VM's hostname, public IP address, HTTP URL, and SSH private key
		ctx.Export("ip", address.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return *addr.IpAddress, nil
		}).(pulumi.StringOutput))

		ctx.Export("hostname", address.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return *addr.DnsSettings.Fqdn, nil
		}).(pulumi.StringOutput))

		ctx.Export("url", address.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return fmt.Sprintf("http://%s:%s", *addr.DnsSettings.Fqdn, servicePort), nil
		}).(pulumi.StringOutput))

		ctx.Export("privatekey", sshKey)

		return nil
	})
}

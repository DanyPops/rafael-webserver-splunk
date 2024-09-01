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
	"time"

	"github.com/pulumi/pulumi-azure-native-sdk/compute/v2"
	"github.com/pulumi/pulumi-azure-native-sdk/network/v2"
	"github.com/pulumi/pulumi-azure-native-sdk/resources/v2"
	"github.com/pulumi/pulumi-command/sdk/go/command/local"
	"github.com/pulumi/pulumi-command/sdk/go/command/remote"
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

	if err := os.Chmod(privateKeyPath, 0600); err != nil {
		return err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(pub), 0644)
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Import configuration settings
		cfg := config.New(ctx, "")
		namePrefix, err := cfg.Try("namePrefix")
		if err != nil {
			namePrefix = "rafael"
		}

		// vmSize, err := cfg.Try("vmSize")
		// if err != nil {
		// 	vmSize = "Standard_B1ms"
		// }

		linuxImage, err := cfg.Try("linuxImage")
		if err != nil {
			linuxImage = "Debian:debian-11:11:latest"
		}

		adminUsername, err := cfg.Try("adminUsername")
		if err != nil {
			adminUsername = "rafael"
		}

		if err != nil {
			return err
		}

		nginxPort, err := cfg.Try("webserverPort")
		if err != nil {
			nginxPort = "80"
		}

		splunkPort, err := cfg.Try("splunkPort")
		if err != nil {
			splunkPort = "8000"
		}

		sshKeyPath, err := cfg.Try("sshKeyPath")
		if err != nil {
			sshKeyPath = os.Getenv("HOME") + "/.ssh/az-rafael-host-vm"
		}
		sshPubKeyPath := sshKeyPath + ".pub"

		// Geneate passwords
		splunkPassword, err := random.NewRandomPassword(ctx, "splunkPassword", &random.RandomPasswordArgs{
			Length: pulumi.Int(16),
		})
		splunkSecret := pulumi.ToSecret(splunkPassword.Result)
		ctx.Export("splunkPassword", splunkSecret)

		winPassword, err := random.NewRandomPassword(ctx, "windowsPassword", &random.RandomPasswordArgs{
			Length: pulumi.Int(16),
		})
		winSecret := pulumi.ToSecret(winPassword.Result)
		ctx.Export("windowsPassword", winSecret)

		pfxPassword, err := random.NewRandomPassword(ctx, "pfxdowsPassword", &random.RandomPasswordArgs{
			Length: pulumi.Int(16),
		})
		pfxSecret := pulumi.ToSecret(pfxPassword.Result)
		ctx.Export("pfxPassword", pfxSecret)

		// Cloud-Init is a Linux VM configuration developed by the OpenStack project
		cloudInit, err := os.ReadFile("./cloud-init.yaml")
		if err != nil {
			return err
		}

		// Create SSH key pair if doesn't exist
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

		linuxVmName := pulumi.String(fmt.Sprintf("%s-linux", namePrefix))
		windowsVmName := pulumi.String(fmt.Sprintf("%s-windows", namePrefix))

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
		}, pulumi.IgnoreChanges([]string{"subnets"}))
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
		linuxDomainLabelSuffix, err := random.NewRandomString(ctx, "linuxDomainLabel", &random.RandomStringArgs{
			Length:  pulumi.Int(8),
			Upper:   pulumi.Bool(false),
			Special: pulumi.Bool(false),
		})
		if err != nil {
			return err
		}

		linuxDomainLabel := linuxDomainLabelSuffix.Result.ApplyT(func(result string) string {
			return fmt.Sprintf("%s-%s", namePrefix, result)
		}).(pulumi.StringOutput)

		// Create a public IP address for the Linux VM
		linuxPubIp, err := network.NewPublicIPAddress(ctx, "linuxPublicIp", &network.PublicIPAddressArgs{
			ResourceGroupName:        rGroup.Name,
			PublicIPAllocationMethod: pulumi.StringPtr("Dynamic"),
			DnsSettings: network.PublicIPAddressDnsSettingsArgs{
				DomainNameLabel: linuxDomainLabel,
			},
		})
		if err != nil {
			return err
		}

		// Create a security group allowing inbound access over ports for SSH, NGINX & Splunk
		linuxSecurityGroup, err := network.NewNetworkSecurityGroup(ctx, "linuxSecurityGroup", &network.NetworkSecurityGroupArgs{
			ResourceGroupName: rGroup.Name,
			SecurityRules: network.SecurityRuleTypeArray{
				network.SecurityRuleTypeArgs{
					Name:                     pulumi.StringPtr(fmt.Sprintf("%s-linux-securityrule", namePrefix)),
					Priority:                 pulumi.Int(1000),
					Direction:                pulumi.String("Inbound"),
					Access:                   pulumi.String("Allow"),
					Protocol:                 pulumi.String("Tcp"),
					SourcePortRange:          pulumi.StringPtr("*"),
					SourceAddressPrefix:      pulumi.StringPtr("*"),
					DestinationAddressPrefix: pulumi.StringPtr("*"),
					DestinationPortRanges: pulumi.ToStringArray([]string{
						nginxPort,
						splunkPort,
						"22",
					}),
				},
			},
		})
		if err != nil {
			return err
		}

		// Create a network interface with the virtual network, IP address, and security group
		linuxNic, err := network.NewNetworkInterface(ctx, "linuxNic", &network.NetworkInterfaceArgs{
			ResourceGroupName: rGroup.Name,
			NetworkSecurityGroup: &network.NetworkSecurityGroupTypeArgs{
				Id: linuxSecurityGroup.ID(),
			},
			IpConfigurations: network.NetworkInterfaceIPConfigurationArray{
				&network.NetworkInterfaceIPConfigurationArgs{
					Name:                      pulumi.String(fmt.Sprintf("%s-ipconfiguration", namePrefix)),
					PrivateIPAllocationMethod: pulumi.String("Dynamic"),
					Subnet: &network.SubnetTypeArgs{
						Id: subnet.ID(),
					},
					PublicIPAddress: &network.PublicIPAddressTypeArgs{
						Id: linuxPubIp.ID(),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		// Create the Linux virtual machine
		linuxVm, err := compute.NewVirtualMachine(ctx, "linuxVm", &compute.VirtualMachineArgs{
			ResourceGroupName: rGroup.Name,
			NetworkProfile: &compute.NetworkProfileArgs{
				NetworkInterfaces: compute.NetworkInterfaceReferenceArray{
					&compute.NetworkInterfaceReferenceArgs{
						Id:      linuxNic.ID(),
						Primary: pulumi.Bool(true),
					},
				},
			},
			HardwareProfile: &compute.HardwareProfileArgs{
				VmSize: pulumi.StringPtr("Standard_B1ms"),
			},
			OsProfile: &compute.OSProfileArgs{
				ComputerName:  linuxVmName,
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

		// Once the machine is created, fetch its IP linuxAddress and DNS hostname
		linuxAddress := linuxVm.ID().ApplyT(func(_ pulumi.ID) network.LookupPublicIPAddressResultOutput {
			return network.LookupPublicIPAddressOutput(ctx, network.LookupPublicIPAddressOutputArgs{
				ResourceGroupName:   rGroup.Name,
				PublicIpAddressName: linuxPubIp.Name,
			})
		})

		// Export the VMs hostname, public IP address, HTTP URL, and SSH private key
		linuxPubIpAddress := linuxAddress.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return *addr.IpAddress, nil
		}).(pulumi.StringOutput)
		ctx.Export("linuxIp", linuxPubIpAddress)

		linuxPubFqdn := linuxAddress.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return *addr.DnsSettings.Fqdn, nil
		}).(pulumi.StringOutput)
		ctx.Export("linuxFqdn", linuxPubFqdn)

		ctx.Export("webserverUrl", linuxAddress.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return fmt.Sprintf("http://%s:%s", *addr.DnsSettings.Fqdn, nginxPort), nil
		}).(pulumi.StringOutput))

		ctx.Export("splunkUrl", linuxAddress.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
			return fmt.Sprintf("https://%s:%s", *addr.DnsSettings.Fqdn, splunkPort), nil
		}).(pulumi.StringOutput))

		// winDomainLabelSuffix, err := random.NewRandomString(ctx, "winDomainLabel", &random.RandomStringArgs{
		// 	Length:  pulumi.Int(8),
		// 	Upper:   pulumi.Bool(false),
		// 	Special: pulumi.Bool(false),
		// })
		// if err != nil {
		// 	return err
		// }

		// winDomainLabel := winDomainLabelSuffix.Result.ApplyT(func(result string) string {
		// 	return fmt.Sprintf("%s-%s", namePrefix, result)
		// }).(pulumi.StringOutput)

		// winPubIp, err := network.NewPublicIPAddress(ctx, "windowsPublicIp", &network.PublicIPAddressArgs{
		// 	ResourceGroupName:        rGroup.Name,
		// 	PublicIPAllocationMethod: pulumi.StringPtr("Dynamic"),
		// 	DnsSettings: network.PublicIPAddressDnsSettingsArgs{
		// 		DomainNameLabel: winDomainLabel,
		// 	},
		// })
		// if err != nil {
		// 	return err
		// }

		winSecurityGroup, err := network.NewNetworkSecurityGroup(ctx, "windowsSecurityGroup", &network.NetworkSecurityGroupArgs{
			ResourceGroupName: rGroup.Name,
			SecurityRules: network.SecurityRuleTypeArray{
				network.SecurityRuleTypeArgs{
					Name:                     pulumi.StringPtr(fmt.Sprintf("%s-windows-securityrule", namePrefix)),
					Priority:                 pulumi.Int(1000),
					Direction:                pulumi.String("Inbound"),
					Access:                   pulumi.String("Allow"),
					Protocol:                 pulumi.String("Tcp"),
					SourcePortRange:          pulumi.StringPtr("*"),
					SourceAddressPrefix:      pulumi.StringPtr("*"),
					DestinationAddressPrefix: pulumi.StringPtr("*"),
					DestinationPortRanges: pulumi.ToStringArray([]string{
						"22",
					}),
				},
			},
		})
		if err != nil {
			return err
		}

		// Create a network interface for Windows VM
		windowsNic, err := network.NewNetworkInterface(ctx, "windowsNic", &network.NetworkInterfaceArgs{
			ResourceGroupName: rGroup.Name,
			NetworkSecurityGroup: &network.NetworkSecurityGroupTypeArgs{
				Id: winSecurityGroup.ID(),
			},
			IpConfigurations: network.NetworkInterfaceIPConfigurationArray{
				&network.NetworkInterfaceIPConfigurationArgs{
					Name: pulumi.String("ipconfig1"),
					Subnet: &network.SubnetTypeArgs{
						Id: subnet.ID(),
					},
					PrivateIPAllocationMethod: pulumi.String("Dynamic"),
					// PublicIPAddress: &network.PublicIPAddressTypeArgs{
					// 	Id: winPubIp.ID(),
					// },
				},
			},
		})
		if err != nil {
			return err
		}

		// Create Windows VM
		winVm, err := compute.NewVirtualMachine(ctx, "windowsVM", &compute.VirtualMachineArgs{
			ResourceGroupName: rGroup.Name,
			NetworkProfile: &compute.NetworkProfileArgs{
				NetworkInterfaces: compute.NetworkInterfaceReferenceArray{
					&compute.NetworkInterfaceReferenceArgs{
						Id: windowsNic.ID(),
					},
				},
			},
			HardwareProfile: &compute.HardwareProfileArgs{
				VmSize: pulumi.StringPtr("Standard_B1ms"),
			},
			OsProfile: &compute.OSProfileArgs{
				ComputerName:  windowsVmName,
				AdminUsername: pulumi.String(adminUsername),
				AdminPassword: winSecret.ApplyT(func(s string) *string {
					return &s
				}).(pulumi.StringPtrInput),
				WindowsConfiguration: &compute.WindowsConfigurationArgs{
					EnableAutomaticUpdates: pulumi.Bool(true),
				},
			},
			StorageProfile: &compute.StorageProfileArgs{
				ImageReference: &compute.ImageReferenceArgs{
					Publisher: pulumi.String("MicrosoftWindowsServer"),
					Offer:     pulumi.String("WindowsServer"),
					Sku:       pulumi.String("2022-datacenter-g2"),
					Version:   pulumi.String("latest"),
				},
				OsDisk: &compute.OSDiskArgs{
					CreateOption: pulumi.String("FromImage"),
				},
			},
		})
		if err != nil {
			return err
		}

		// winAddress := linuxVm.ID().ApplyT(func(_ pulumi.ID) network.LookupPublicIPAddressResultOutput {
		// 	return network.LookupPublicIPAddressOutput(ctx, network.LookupPublicIPAddressOutputArgs{
		// 		ResourceGroupName:   rGroup.Name,
		// 		PublicIpAddressName: winPubIp.Name,
		// 	})
		// })

		// winPubIpAddress := winAddress.ApplyT(func(addr network.LookupPublicIPAddressResult) (string, error) {
		// 	return *addr.IpAddress, nil
		// }).(pulumi.StringOutput)
		// ctx.Export("winIp", winPubIpAddress)

		winInstallSsh, err := compute.NewVirtualMachineExtension(ctx, "windowsOpenSSH", &compute.VirtualMachineExtensionArgs{
			ResourceGroupName:  rGroup.Name,
			VmName:             winVm.Name,
			Type:               pulumi.String("WindowsOpenSSH"),
			Publisher:          pulumi.String("Microsoft.Azure.OpenSSH"),
			TypeHandlerVersion: pulumi.String("3.0"),
		})
		if err != nil {
			return err
		}

    // Distribute public SSH key to Windows Server
  //   winDistPubSshKey, err := compute.NewVirtualMachineRunCommandByVirtualMachine(ctx, "distributePublicKeyToWindows", &compute.VirtualMachineRunCommandByVirtualMachineArgs{
  //     ResourceGroupName: rGroup.Name,
  //     VmName: winVm.Name,
  //     Location: winVm.Location,
  //     Source: &compute.VirtualMachineRunCommandScriptSourceArgs{
  //       Script: pulumi.Sprintf(`powershell -command '$username = '%s'; $homeDirectoryPath = "C:\Users\$username"; New-Item -ItemType Directory -Force "C:\Users\$username\.ssh"; Set-Content -Path "C:\Users\$username\.ssh\authorized_keys" -Value '%s'; $acl = Get-Acl "$homeDirectoryPath"; $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$username", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"); $acl.SetAccessRule($accessRule); Set-Acl -Path "$homeDirectoryPath" -AclObject "$acl"'`,
		// 			adminUsername,
		// 			sshPubKey),
  //     },
		// }, pulumi.DependsOn([]pulumi.Resource{
  //     winInstallSsh,
		// }))
		// if err != nil {
		// 	return err
		// }

		ctx.Export("privateKey", sshKey)
		ctx.Export("privateKeyPath", pulumi.String(sshKeyPath))

		// Generate Ansible inventory
		ansibleDir := pulumi.All(linuxVmName, windowsVmName).ApplyT(func(args []interface{}) (string, error) {
			conf := AnsibleConfiguration{
				Linux:   args[0].(string),
				Windows: args[1].(string),
			}

			dir, err := GenerateConfiguration(conf)
			if err != nil {
				return "", err
			}

			return dir, nil
		}).(pulumi.StringOutput)
		ctx.Export("ansibleDir", ansibleDir)

		// Distribute private SSH key to Ansible Controller
		distKey, err := local.NewCommand(ctx, "distributeKeyToController", &local.CommandArgs{
			Create: pulumi.String(fmt.Sprintf("scp -o StrictHostKeyChecking=no " +
				"-o ConnectionAttempts=30 " +
				"-o ConnectTimeout=10 " +
				"-i $RAFAEL_SSH_KEY " +
				"$RAFAEL_SSH_KEY " +
				"$RAFAEL_ADMIN@$RAFAEL_CONTROLLER_HOSTNAME:/home/$RAFAEL_ADMIN/.ssh/id_rsa")),
			Environment: pulumi.StringMap{
				"RAFAEL_SSH_KEY":             pulumi.String(sshKeyPath),
				"RAFAEL_ADMIN":               pulumi.String(adminUsername),
				"RAFAEL_CONTROLLER_HOSTNAME": linuxPubIpAddress,
			},
		}, pulumi.DependsOn([]pulumi.Resource{
      winInstallSsh,
			linuxVm,
		}))
		if err != nil {
			return err
		}

		// Run Ansible directory
		distAnsible, err := local.NewCommand(ctx, "distributeAnsibleToController", &local.CommandArgs{
			Create: pulumi.String(fmt.Sprintf("scp -o StrictHostKeyChecking=no " +
				"-o ConnectionAttempts=30 " +
				"-o ConnectTimeout=10 " +
				"-i $RAFAEL_SSH_KEY " +
				"-r $RAFAEL_ANSIBLE_DIR/. " +
				"$RAFAEL_ADMIN@$RAFAEL_CONTROLLER_HOSTNAME:/home/$RAFAEL_ADMIN/ansible")),
			Environment: pulumi.StringMap{
				"RAFAEL_SSH_KEY":             pulumi.String(sshKeyPath),
				"RAFAEL_ADMIN":               pulumi.String(adminUsername),
				"RAFAEL_CONTROLLER_HOSTNAME": linuxPubIpAddress,
				"RAFAEL_ANSIBLE_DIR":         ansibleDir,
			},
		}, pulumi.DependsOn([]pulumi.Resource{
			distKey,
		}))
		if err != nil {
			return err
		}

		// Run Ansible playbook
		_, err = remote.NewCommand(ctx, "runAnsiblePlaybook", &remote.CommandArgs{
			Connection: &remote.ConnectionArgs{
				Host: linuxPubIpAddress,
				Port: pulumi.Float64(22),
				User: pulumi.String(adminUsername),
				PrivateKey: sshKey.ApplyT(func(s string) *string {
					return &s
				}).(pulumi.StringPtrOutput),
			},
			Create: pulumi.All(linuxVmName, linuxPubFqdn, winSecret, pfxSecret, splunkSecret).ApplyT(func(args []interface{}) *string {
				command := "sudo usermod -aG docker $USER; " +
					"until command -v ansible-playbook >& /dev/null; do sleep 5; done; " +
					"cd \"$HOME/ansible\" || exit 1; " +
					"ansible-galaxy install -g -f -r \"$HOME/ansible/requirements.yml\"; " +
					"ansible-playbook \"$HOME/ansible/deploy.yml\" " +
					"-i $HOME/ansible/inventory.yml -u $USER " +
					fmt.Sprintf("-e 'linux_host=%s' ", args[0].(string)) +
					fmt.Sprintf("-e 'linux_fqdn=%s' ", args[1].(string)) +
					fmt.Sprintf("-e 'ansible_password=%s' ", args[2].(string)) +
					fmt.Sprintf("-e 'pfx_password=%s' ", args[3].(string)) +
					fmt.Sprintf("-e 'splunk_password=%s' ", args[4].(string))
				return &command
			}).(pulumi.StringPtrOutput),
			Triggers: pulumi.Array{pulumi.String(time.Now().Format(time.Now().Format(time.RFC3339)))},
		}, pulumi.DependsOn([]pulumi.Resource{
			distAnsible,
		}))
		if err != nil {
			return err
		}

		return nil
	})
}

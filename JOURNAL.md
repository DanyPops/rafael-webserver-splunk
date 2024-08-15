Planning Phase
Personal goal
Beyond the goals set by the task, I aim for simple & agnostic code that can used by anyone to deploy the environment in a quick & easy manner.

Toolbox
Deciding on Infrastructure
Initially, I desired to remain local & deploy the environment on VirtualBox using a provider & provide a Vagrant 'toolbox' VM but due to using musl standard library instead of glibc I faced technical issues.
I setteled on Azure instead since an Active Directory service is required & Azure is a Microsoft product so superb integration is expected.

Deciding on IaC
In the current scenario, the choice of Terraform & Pulumi is a personal preference, I chose Pulumi. 
Terraform is mature, as such documentation is plenty, & it uses a DSL so it's great for 'Ops' background folk. 
Pulumi is more dynamic due to its programming library nature & caters to 'Devs'.

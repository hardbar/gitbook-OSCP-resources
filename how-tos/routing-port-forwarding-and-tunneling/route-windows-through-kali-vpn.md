# Route Windows through Kali VPN

## Introduction

* The objective of this "how to" guide is to provide the required configuration steps in order to obtain connectivity between systems within a private network and an external VPN network via a Linux VM with IP Forwarding enabled.
* The connections from the private network will be NATTED on the Linux VM via iptables and traffic will be routed accordingly.
* The network shown below will be used to illustrate the required configurations. In this example, we will be connecting a Windows VM to the hackthebox network via a VPN connection established through the Linux VM.

## Prerequisites

* In this example, we are only using two VMs, however, theoretically you could add as many as you want. The two VMs are running in VMWare Player which has been installed on a Windows 10 host machine, however, deploying a similar setup in Virtual box on Windows or Linux using the same concepts should be fairly straightforward.
* Windows VM - Running Windows 10, but could be any version where you can add static routes.
* Linux VM - Running Kali, but could also be any Linux or Unix based OS that supports IP Forwarding and NAT.
* Each VM has two network interface cards:&#x20;
  * One interface in the "Custom VMnet2" network. The network number is arbitrary, but both VMs must have an interface in the same private/custom network.
  * One interface connected to the host via either a NAT or a Bridged interface. This is not strictly required for the Windows VM, but if you need internet access or access to your physical network then you'll need to add this. It is required for the Linux VM in order to connect to the VPN target via the internet.
* For the example network setup shown in the diagram below, we'll assign and use the 192.168.10.0/29 subnet for the VM to VM connection via VMnet2.
* The subnet/s in the target VPN network. An easy way to obtain this information is to check the route table on the Linux VM after establishing the VPN connection to the target network. This information should be gathered before proceeding.

![](../../.gitbook/assets/ip\_forwarding1.JPG)

{% hint style="warning" %}
This guide does not show how to install the VM software or VM machines or the configuration of the private/custom network between the two VM machines.&#x20;

In VMWare Player connecting two VM machines is as simple as selecting the same network from the "Custom: Specific virtual network" drop down list after adding a second adapter.&#x20;

Other virtualization software may be slightly different, but there are many helpful guides online to assist with this, and so it will not be covered here.
{% endhint %}

## Configure the Windows VM

In order for the Windows VM to communicate with the systems on the other side of the VPN connection via the Linux VM, we need to configure the following:

* An IP address in the same subnet as the Kali VM on the VM only network. We'll be using "VMnet2" for this example. A default gateway does not need to be set on this interface.
* Add static route/s for the subnets that exist on the other side of the VPN connection.&#x20;
* Configure the Windows VM with the 192.168.10.2/255.255.255.248 IP address.
* Add a static route pointing to the IP address of the interface on the Linux VM in the private/custom network. In this case the subnet we are adding is 10.10.10.0/23, which is the network that hosts the hackthebox target machines.

```
route add 10.10.10.0/23 MASK 255.255.254.0 192.168.10.1
```

{% hint style="warning" %}
If you have Windows Firewall enabled, you'll need to make sure that the connectivity is allowed through it as well.
{% endhint %}

## Configure the Linux VM

In order to allow traffic to be routed through the Linux VM, we'll need to configure the following:

* Enable IP forwarding on the Linux VM. This will allow us to route traffic through the VM to the target networks.

{% hint style="warning" %}
NOTE: The configuration may differ slightly, depending on which flavour of Linux you are using, however, these are fairly simple changes to make and there are alot of resources online to help.
{% endhint %}

* Check the current state of IP Forwarding:

```
cat /proc/sys/net/ipv4/ip_forward --> If the output = 0, it's disabled, if it's 1 it's already enabled

OR

sysctl net.ipv4.ip_forward --> If the output = 0, it's disabled, if it's 1 it's already enabled

```

* If it is not enabled already, it can be enabled as follows:

```
sudo echo 1 > /proc/sys/net/ipv4/ip_forward

OR

sysctl -w net.ipv4.ip_forward=1

```

* Configure iptables to allow the connections and to NAT them where applicable. The interfaces used in the example configuration are as follows (adjust your configuration as necessary to fit your environment):
  * tun0 - the VPN interface (created when the VPN tunnel is initialized)
  * eth0 - the connection to the outside world (NIC1-Bridged)
  * eth1 - the connection to the private/custom VM network (NIC2-Custom VMnet2)

```
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE 
sudo iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT 
sudo iptables -A FORWARD -i tun0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT

```

* The first rule enables Hide NAT on the tun0 interface. Any connections routed through it will use it's IP address as the source address in the packets sent towards the far end of the VPN tunnel.
* The second rule allows traffic from the private VM network coming into eth1 to the tun0 VPN interface. Traffic that is not destined for the interface itself will be routed according to the route table.
* The third rule allows established connections coming into tun0 from the VPN networks back to the network behind eth1. This allows for the return traffic of the NATTED connections to be matched against a connections table and then routed back towards the Windows VM.

## Testing

* Once all the configurations have been completed, it's time to test the setup.
* Ensure that the VMs can ping each other on the private/custom network.
* Connect the Linux VM to the target VPN network. For example, to connect to the hackthebox network:

```
sudo openvpn lab_Username.vpn
```

* Once the connection has been established, we can verify that we have specified the correct target subnet/s when configuring the static route on the Windows VM:

```
ip route show

OR

route

OR

netstat -r

```

* If there are any additional routes that were missed, simply add a static route for it on the Windows VM as shown in the "Configure the Windows VM" section.
* Finally, start a target machine of your choice via the hackthebox interface and ping it from within the Windows VM.
* You can check the established connections in the /proc/net/nf\_conntrack file on the Linux VM as follows:&#x20;

```
On the Windows VM: 
C:\WINDOWS\system32>ping 10.10.10.48 -t
Pinging 10.10.10.48 with 32 bytes of data: 
Reply from 10.10.10.48: bytes=32 time=18ms TTL=126
...

On the Linux VM (Kali): 
$ sudo tail -f /proc/net/nf_conntrack
ipv4 2 icmp 1 25 src=192.168.10.2 dst=10.10.10.48 type=8 code=0 id=1 src=10.10.10.48 dst=10.10.15.6 type=0 code=0 id=1 mark=0 zone=0 use=2

```

In the output above:

* 192.168.10.2 --> IP address on the Windows VM on VMnet2
* 10.10.10.48 --> target machine on the hackthebox network (Nineveh)
* 10.10.15.6 --> IP address assigned to tun0 after VPN established

## Troubleshooting

If you cannot ping a target machine on the VPN network, you can try the following checks to narrow down where the issue could be:

* Verify the two VMs both have an interface in the same network that is not the host machine network, for example, a VM only network such as VMnet2 in our sample network.
* Verify the two VMs both have an IP address on the same subnet in the VM only network.
* Verify the two VMs can ping each other via the interfaces in the VM only network. Test from both VMs. Run wireshark or tcpdump and capture ICMP packets to see if packets are reaching the correct interfaces. Adjust the captures to check each interface sequentially or capture on all interfaces and filter on ICMP.
* Verify the routing on the Windows VM. Confirm that the route has been added for the target network/s and that it is going via the correct interface.
* Verify that the firewall on the Windows VM isn't dropping or blocking traffic.
* Verify that any iptables rules added other than the ones shown in this guide are not blocking the connections.
* Verify that the VPN has been established and that the tun0 interface has received an IP address, and that the route table contains the target networks via the VPN interface.
* Start a virtual machine on the hackthebox network and verify you can ping it from the Linux VM.
* Verify that the iptables rules shown in this guide are correctly configured. Make sure to adjust the interfaces to match you environment if your interfaces are named differently.&#x20;
* Verify that you can see the connections in the connections table on the Linux VM via the /proc/net/nf\_conntrack file (this is the file in Kali, but it may be different in other OS's, however, it should be in the /proc/net directory somewhere).

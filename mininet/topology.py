"""
Mininet Custom Topology for AI-Driven DDoS Detection and Mitigation Framework
Topology:
- 4 Attacker hosts (h1, h2, h3, h4)
- 2 Legitimate clients (h5, h6)
- 1 Protected Server (h7: 10.0.0.100)
- 1 OpenFlow 1.3 Switch (s1)
- Remote Ryu Controller (127.0.0.1:6653)
"""
try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    class Topo:
        pass

class DDoSTopology(Topo):
    def build(self):
        # Add single OpenFlow 1.3 switch
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Add 4 Attacker hosts
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Add 2 Legitimate client hosts
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')

        # Add 1 Protected Server host
        h7 = self.addHost('h7', ip='10.0.0.100/24', mac='00:00:00:00:00:07')

        # Connect all hosts to switch s1
        for h in [h1, h2, h3, h4, h5, h6, h7]:
            self.addLink(h, s1)

def run_network():
    if not MININET_AVAILABLE:
        print("[Notice] Mininet requires Linux kernel network namespaces.")
        print("To run Mininet on Linux / WSL2 / Docker, execute: sudo python3 mininet/topology.py")
        return

    setLogLevel('info')
    topo = DDoSTopology()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, controller=c0, switch=OVSSwitch)

    info('*** Starting Network ***\n')
    net.start()

    # Start simple web servers on protected server h7
    h7 = net.get('h7')
    h7.cmd('python3 -m http.server 80 &')
    info('*** Web server listening on h7 (10.0.0.100:80) ***\n')

    CLI(net)

    info('*** Stopping Network ***\n')
    net.stop()

if __name__ == '__main__':
    run_network()

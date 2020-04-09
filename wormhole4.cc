/* Wormhole Attack Simulation with AODV Routing Protocol - Sample Program
 */

#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/netanim-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "myapp.h"
#include <fstream>

NS_LOG_COMPONENT_DEFINE ("Wormhole");

using namespace ns3;
int cnt=0;
double resultMatrix[4][20];

void
ReceivePacket(Ptr<const Packet> p, const Address & addr)
{
  cnt+=1;
  //std::cout << Simulator::Now ().GetSeconds () << "\t" << p->GetSize() <<"\n";
}


int main (int argc, char *argv[])
{
  bool enableFlowMonitor = false;
  bool AttackStat = false;
int pcktCnt = 50;
  int maxLimit = 100;
  int stepCount = 5;
  std::string phyMode ("DsssRate1Mbps");
  int SuspNode1 = 0;
  int SuspNode2 = 0;
  CommandLine cmd;
  cmd.AddValue ("EnableMonitor", "Enable Flow Monitor", enableFlowMonitor);
  cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
  cmd.AddValue ("AttackStat","Wormhole attack enabled or disabled",AttackStat);
  cmd.AddValue ("pcktCnt","number of packets to be sent during each simulation",pcktCnt);
  //cmd.AddValue ("maxLimit","Max Limit for packet analysis",maxLimit);
  //cmd.AddValue ("stepCount","Step count for regular incrementation",stepCount);

  cmd.AddValue ("SuspNode1","first node to be suspected",SuspNode1);
  cmd.AddValue ("SuspNode2","Second node to be suspected",SuspNode2);

  cmd.Parse (argc, argv);



  int loopLimit = maxLimit/stepCount;
  //std::cout<<pcktCnt<<"\n";


//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer c; // ALL Nodes
  NodeContainer not_malicious;
  NodeContainer malicious;
  c.Create(6);

  not_malicious.Add(c.Get(0));
  not_malicious.Add(c.Get(3));
  not_malicious.Add(c.Get(4));
  not_malicious.Add(c.Get(5));
  malicious.Add(c.Get(1));
  malicious.Add(c.Get(2));
  // Set up WiFi
  WifiHelper wifi;

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11);

  YansWifiChannelHelper wifiChannel ;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::TwoRayGroundPropagationLossModel",
                                  "SystemLoss", DoubleValue(1),
                                "HeightAboveZ", DoubleValue(1.5));

  // For range near 250m
  wifiPhy.Set ("TxPowerStart", DoubleValue(33));
  wifiPhy.Set ("TxPowerEnd", DoubleValue(33));
  wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
  wifiPhy.Set ("TxGain", DoubleValue(0));
  wifiPhy.Set ("RxGain", DoubleValue(0));
  wifiPhy.Set ("RxSensitivity", DoubleValue(-61.8));
  wifiPhy.Set ("CcaEdThreshold", DoubleValue(-64.8));

  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a non-QoS upper mac
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  // Set 802.11b standard
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue(phyMode),
                                "ControlMode",StringValue(phyMode));


  NetDeviceContainer devices, mal_devices;
  devices = wifi.Install (wifiPhy, wifiMac, c);
  mal_devices = wifi.Install(wifiPhy, wifiMac, malicious);

  wifiPhy.EnablePcapAll("aodv");

//  Enable AODV
  AodvHelper aodv;
  AodvHelper malicious_aodv; 
 

  // Set up internet stack
  InternetStackHelper internet;
  internet.SetRoutingHelper (aodv);
  internet.Install (not_malicious);
  
  malicious_aodv.Set("EnableWrmAttack",BooleanValue(AttackStat)); // putting *false* instead of *true* would disable the malicious behavior of the node

  malicious_aodv.Set("FirstWifiEndOfWormTunnel",Ipv4AddressValue("10.0.1.2"));
  malicious_aodv.Set("SecondWifiEndOfWormTunnel",Ipv4AddressValue("10.0.1.3"));

  internet.SetRoutingHelper (malicious_aodv);
  internet.Install (malicious);

  // Set up Addresses
  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.0.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifcont = ipv4.Assign (devices);

  ipv4.SetBase ("10.1.2.0", "255.255.255.0");
  Ipv4InterfaceContainer mal_ifcont = ipv4.Assign (mal_devices);



  NS_LOG_INFO ("Create Applications.");

  // UDP connection from N0 to N3

  uint16_t sinkPort = 6;
  Address sinkAddress (InetSocketAddress (ifcont.GetAddress (3), sinkPort)); // interface of n3
  PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), sinkPort));
  ApplicationContainer sinkApps = packetSinkHelper.Install (c.Get (3)); //n3 as sink
  sinkApps.Start (Seconds (0.));
  sinkApps.Stop (Seconds (100.));

  Ptr<Socket> ns3UdpSocket = Socket::CreateSocket (c.Get (0), UdpSocketFactory::GetTypeId ()); //source at n0





// Set Mobility for all nodes

  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
  positionAlloc ->Add(Vector(100, 0, 0)); // node0
  positionAlloc ->Add(Vector(200, 0, 0)); // node1 
  positionAlloc ->Add(Vector(450, 0, 0)); // node2
  positionAlloc ->Add(Vector(550, 0, 0)); // node3
  positionAlloc ->Add(Vector(200, 10, 0)); // node4
  positionAlloc ->Add(Vector(450, 10, 0)); // node5


  mobility.SetPositionAllocator(positionAlloc);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(c);


int cords[] = {0,550,200,500,400,500,600,550,200,600,400,600};

  AnimationInterface anim ("wormhole.xml"); // Mandatory

    //std::cout<<"Suspected Node pairs are :-----> "<<SuspNode1<< " and " <<SuspNode2<<"\n";
    //std::cout<<"Attack status------------------> "<<AttackStat<<"\n";
  for(int i=0;i<6;i++){
    if((SuspNode1-1) == i){
      AnimationInterface::SetConstantPosition (c.Get (i), -1000,-1000);
    }
    else if((SuspNode2-1) == i){
      AnimationInterface::SetConstantPosition (c.Get (i), -1000,-1000);
    }
    else
    AnimationInterface::SetConstantPosition (c.Get (i), cords[i+i], cords[i+i+1]);
  }




//   AnimationInterface anim ("wormhole.xml"); // Mandatory
//   AnimationInterface::SetConstantPosition (c.Get (0), 0, 550);
//   AnimationInterface::SetConstantPosition (c.Get (1), 200, 500);
//   AnimationInterface::SetConstantPosition (c.Get (2), 400, 500);
//   AnimationInterface::SetConstantPosition (c.Get (3), 600, 550); 
//   AnimationInterface::SetConstantPosition (c.Get (4), 200, 600);
//   AnimationInterface::SetConstantPosition (c.Get (5), 400, 600);
   anim.EnablePacketMetadata(true);

//
// Calculate Throughput using Flowmonitor
//
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll();

  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> ("wormholeStage3.routes", std::ios::out);
  aodv.PrintRoutingTableAllAt (Seconds (41), routingStream);

  /*std::ofstream fout;
  if(!AttackStat){
    fout.open("resultsBeforeAttackStage3.csv");
  }
  else{
    fout.open("resultsAfterAttackStage3.csv");
  }*/


  //std::cout<<"Accumulating results...\n";
  //std::cout<<"Generating result matrix...\n";

  for (int i = 0; i < loopLimit; ++i)
  {
    /* code */

    // Create UDP application at n0
    Ptr<MyApp> app = CreateObject<MyApp> ();
    app->Setup (ns3UdpSocket, sinkAddress, 1024, pcktCnt, DataRate ("128Kbps"));
    c.Get (0)->AddApplication (app);


    // Trace Received Packets
    Config::ConnectWithoutContext("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", MakeCallback (&ReceivePacket));

    app->SetStartTime (Seconds (40.));
    app->SetStopTime (Seconds (100.));



//
// Now, do the actual simulation.
//
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds(100.0));
  Simulator::Run ();
  monitor->StartRightNow();

  monitor->CheckForLostPackets ();

  pcktCnt+=stepCount;
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  uint32_t txPacketsum = 0;
  uint32_t rxPacketsum = 0;
  uint32_t rxBytesum = 0;
  double DropPacketsum = 0;
  uint32_t LostPacketsum = 0;
  //double packet_loss_threshold = 2.0;
  //double delay_threshold = 1.5;
  double Delaysum = 0;
  //double etf = 40 ;
  int j = 0;
  int count =0;
  double avg = 0;
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
    //Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);

     //std::cout << j + 1 << std::endl;
    j++;
    //for counting the total result
    txPacketsum += i->second.txPackets;
    rxPacketsum += i->second.rxPackets;
    rxBytesum += i->second.rxBytes;
    LostPacketsum += i->second.lostPackets;
    //DropPacketsum += i->second.packetsDropped.size();
    for (uint32_t j = 0; j < i->second.packetsDropped.size(); j++) {
      DropPacketsum += i->second.packetsDropped[j];
      std::cout<<i->second.packetsDropped[j];
    }

    Delaysum += i->second.delaySum.GetSeconds();

       //if ((t.sourceAddress && t.destinationAddress))
       //{
          count+=1;
          // std::cout << "  Flow " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
          // std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
          // std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
          // std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
           avg+=i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024;
       //}
    
     }


  //Results in form:
  // [Throughput (in Kbps)] [Packets Delivery Ratio (in %)] [Average END-TO-END delay: ] 
  std::cout << ((double)(avg/count)) << "\t"
            << ((rxPacketsum * 100) /txPacketsum) << "\t"
            << ((Delaysum )/ txPacketsum*rxPacketsum) << "\n";
  //std::cout << "Recvd Pckts : "<< pcktCnt <<"\n ";



Simulator::Stop();
//Simulator::Destroy();



  monitor->SerializeToXmlFile("lab-4.flowmon", true, true);
/*
  resultMatrix[0][i] = pcktCnt;
  resultMatrix[1][i] = (avg/count);
  resultMatrix[2][i] = ((rxPacketsum * 100) /txPacketsum);
  resultMatrix[3][i] = ((Delaysum / txPacketsum) / rxPacketsum) * 1000000;
  
  }

  std::cout<<"Result matrix Generated!!\n";
  std::cout<<"Generating Result File...\n";
  
  for (int i = 0; i < 4; ++i)
  {
    //code 
    if(i==0){fout<<"Packets";}
    else if(i==1){fout<<"Average Throughput (in Kbps)";}
    else if(i==2){fout<<"Packet Delivery Ratio (in %)";}
    else if(i==3){fout<<"Average E2E Delay (in ms)";}
    for (int j = 0; j < loopLimit; ++j)
    {
      fout<<"\t"<<resultMatrix[i][j];
    }

    fout<<"\n";
  }

  std::cout<<"\nResult file Generated!!\n";
  
*/
break;
}

}

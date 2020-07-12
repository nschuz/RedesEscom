
package admin;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;


public class Captura extends Checksum {

   private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }

	public static void main(String[] args) {
		
            
            
            List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

		}//for
                ///////////////
                   
                
                
                

		PcapIf device = alldevs.get(2); // We know we have atleast 1 device
		System.out
		    .printf("\nChoosing '%s' on your behalf:\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam mÃ¡x de trama */

		int snaplen = 64 * 1024;           // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000;           // 10 seconds in millis
                Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}//if

                       /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression =""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
                /****************/


		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **********************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {
                            
                            

                            // creamos la varibale tipo 
                              int tipo=(packet.getUByte(12)*256) + packet.getUByte(13);
                              // creamos un arreglo 
                              byte [] ipPack = packet.getByteArray(14 , packet.size()-14);
                             // System.out.println("Tipo:  "+tipo);
                             
                             System.out.println("\n\n");
				System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
                                for(int i=0;i<packet.size();i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                if(i%16==15)
                                    System.out.println("");
                                }
                                System.out.println("\n\nEncabezado: "+ packet.toHexdump());
                                
                                System.out.println("\n");
                                if(tipo==2048){
                                    System.out.println("--------------------Capa de Red----------------");
                                    int IHL =packet.getUByte(14); // obtenemos le ihl 
                                   IHL=(IHL&0X0F) *4 ; // multiplicammos por 4 y lo limpiamos 
                             //  byte[] check=packet.getByteArray(14,IHL); // obtenemos la trama desde el byte 14 hasta log del encabezado
                                   // System.out.println("Datos del checksum de es: ");
                                  //  for (int i=0; i<IHL; i++){
                                       
                                      //  System.out.printf("%02X",check[i]);// verificamos que la trama que capturamos sea correcta 
                                   // }
                                    System.out.println("IHL: "+IHL);
                                    long VerificarSuma=Checksum.calculateChecksum(packet.getByteArray(14,IHL)); // mandamos a llmar el checksum
                                    if (VerificarSuma==0){// checamos si la suma del checksum nos da 0 
                                        System.out.println("\n");
                                        System.out.println("Checksum en la capa de red correcto");
                                        System.out.println("Ckesum:  "+VerificarSuma);
                                    }else{
                                        System.out.println("\n");
                                        System.out.printf("Checksum en la capa de red incorrecto, el correcto es: %02X",VerificarSuma);
                                       // System.out.printf("%02X",VerificarSuma);
                                        System.out.println("");
                                    }
                                
                                }
                               
                              ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
                                //Para la capa de transporte, el checkum se calcula a partir de la suma de un pseudo encabezado y el PDU de la capa de transporte.
                                /// Finalmente, al sumar el pseudo encabezado y el PDU obtenemos el checksum.
                               // int tipo2=(packet.getUByte(12)*256)+ packet.getUByte(13);
                                System.out.println("");
                               System.out.println("\ntipo: "+tipo);
                               if (tipo>1500){
                                   if (tipo==2048){
                                       System.out.println("-------------Capa de Transporte--------------");
                                     int IHL =packet.getUByte(14); // obtenemos le ihl 
                                    IHL=(IHL&0X0F) *4 ;
                                   int longitudPDU = (packet.getUByte(16)*256) + packet.getUByte(17);
                                   int PDUTransporte=longitudPDU-(IHL);
                                   //byte PDUT= (byte)PDUTransporte;
                                   
                                   byte[ ] PDUt= new byte [(packet.getCaptureHeader().caplen())-34];
                                   
                                   
                                   
                                        // cosntruimos nuestro encabezado 
                                   byte pseudoe[] = new byte [12+longitudPDU];
                                    //ip oriegn   
                                
                                    int i=0;
                                    for (int j = 0; j < 4; j++) {
                                           pseudoe[j]=(byte)packet.getUByte(j+26);
                                           i++;
                                       }
                                   // ip destino
                                   for (int j = 0; j < 4; j++) {
                                           pseudoe[j]=(byte)packet.getUByte(j+30);
                                           i++;
                                       }
                                   i++;
                                       System.out.println("valor de i="+i);
                                   //bytes ceros 
                                   pseudoe[i]=(byte)0x00;
                                   i++;
                                   // longitud
                                 pseudoe[i]=(byte)longitudPDU;
                                 i++;
                                 // protocolo
                                 pseudoe[i]=(byte)packet.getUByte(26);
                                         i++;
                                 
                                 // PDT BYTE 34 A LO QUE FLATA 
                                PDUt=packet.getByteArray(34,PDUTransporte );
                                byte[] tramafinal= new byte [PDUt.length+pseudoe.length];
                               
                                 i=0;
                                for(int j=0; j<pseudoe.length; j++){
                                    tramafinal[j]=pseudoe[i];
                                    i++;
                                    
                                }
                                int l=0;
                                for( int k=i;k<tramafinal.length; k++){
                                    tramafinal[k]=PDUt[l];
                                    l++;
                                }
                                
                                  
                                 long sumacheck=Checksum.calculateChecksum(tramafinal);
                                       System.out.printf("CHECKSUM Calculado en la capa de trasnporte:%02X ",sumacheck);
                                       System.out.println("\n");
                                 
                                   }
                                   
                               };
                             
                         }
                         
			
                        
		};


		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		pcap.loop(3, jpacketHandler, "jNetPcap rocks!");

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();
                }catch(IOException e){e.printStackTrace();}
	}
}

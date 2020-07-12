
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
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

public class Captura {

    /**
     * Main startup method
     *
     * @param args ignored
     */
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

    //bit poll/final(p/f)  |   bit sondeo/fin -----> se indica solamente si esta encendido
    private static void pollFinal(String c_r, int byteRecibido, String version) {
        String p_f = "";
        if (version.equals("Extendida")) {
            if ((c_r.equals("Comando")) == true) {
                p_f = ((byteRecibido & 0x00000001) == 1) ? "P" : "";
                System.out.printf("\n |-->Bit(p/f):  %s", p_f);
            } else if ((c_r.equals("Respuesta")) == true) {
                p_f = ((byteRecibido & 0x00000001) == 1) ? "F" : "";
                System.out.printf("\n |-->Bit(p/f): %s", p_f);
            }
        } else if (version.equals("Reducida")) {

            if ((c_r.equals("Comando")) == true) {
                p_f = (((byteRecibido >> 4) & 0x0001) == 1) ? "P" : "";
                System.out.printf("\n |-->Bit(p/f):  %s\n", p_f);
            } else if ((c_r.equals("Respuesta")) == true) {
                p_f = (((byteRecibido >> 4) & 0x0001) == 1) ? "F" : "";
                System.out.printf("\n |-->Bit(p/f): %s\n", p_f);
            }
        }
    }

    //Numero de secuencia N(s): Cuenta la secuencia de tramas transmitidas (send). 
    private static void numeroSecuencia(int primerByte, String version) {
        int n_s = primerByte >> 1;//& 0x1111111
        if (version.equals("Extendida")) {
            System.out.printf(" |-->Numero de secuencia N(s) version %s:\n\tDecimal: %d \tHexadecimal: %02X", version, n_s, n_s);
        } else if (version.equals("Reducida")) {
            n_s = primerByte & 0x0000111;
            System.out.printf(" |-->Numero de secuencia N(s) version %s:\n\tDecimal: %d \tHexadecimal: %02X", version, n_s, n_s);
        }

    }

    /*Numero de acuse N(r): da el número (Ns) de la trama que la estación que transmite espera recibir.
        tambien conocido como: numero de secuencia de recepcion*/
    private static void numeroAcuse(int byteRecibido, String version) {
        int n_r = byteRecibido >> 1; //& 0x1111111
        if (version.equals("Extendida")) {
            System.out.printf("\n |-->Numero de acuse/recivo version: %s N(r):\n\tDecimal: %d \tHexadecimal: %02X", version, n_r, n_r);
        } else if (version.equals("Reducida")) {
            n_r = byteRecibido >> 4;
            System.out.printf("\n |-->Numero de acuse/recivo version: %s N(r):\n\tDecimal: %d \tHexadecimal: %02X", version, n_r, n_r);
        }
    }

    // Funcion para invertir los bits de un numero entero
    public static int reverseBits(int number) {
        int res = 0;
        System.out.println(">> Byte recibido sin agregar ceros: " + Integer.toBinaryString(number));
        /*Llama a la funcion "addZeros" para poder ser invertida de manera correcta
          de lo contrario no toma en cuenta el primer cero
        A la funcion se le manda el numero como una cadena de bits
         */
        String cadenaTemporal = addZeros(Integer.toBinaryString(number));
        System.out.println(">> Byte recibido con ceros agregados: " + cadenaTemporal);
        //cambia el orden de la cadena, ordena de derecha a izquierda
        String cadenaEnviar = new StringBuilder(cadenaTemporal).reverse().toString();
        System.out.println(">> Byte invertido para analizar: " + cadenaEnviar);
        //Convierte la cadena de bits a un numero entero y lo envia
        res = Integer.parseInt(cadenaEnviar, 2);
        return res;
    }

    //Funcion para agregar cero a la izquierda para poder invertirlo 
    private static String addZeros(String number) {
        //Declaracion de variables
        int i = 0;
        String temp = "";
        //Si la longitud no es de un multiplo de 2 se le agrega un cero
        if (i < 2 - (number.length() % 2)) {
            temp += "0";
        }
        /*A los ceros concatenados en el if anterior se le va a concatenar
        la cadena de bits, si se hace al reves esta mal trabajado
         */
        temp += number;
        //se envia la cadena final
        return temp;
    }

    public static void main(String[] args) {
        Pcap pcap = null;
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
            StringBuilder errbuf = new StringBuilder(); // For any error msgs
            System.out.println("[0]-->Realizar captura de paquetes al vuelo");
            System.out.println("[1]-->Cargar traza de captura desde archivo");
            System.out.print("\nElige una de las opciones:");
            int opcion = Integer.parseInt(br.readLine());
            if (opcion == 1) {

                /////////////////////////lee archivo//////////////////////////
                //String fname = "archivo.pcap";
                String fname = "paquetes3.pcap";
                pcap = Pcap.openOffline(fname, errbuf);
                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: " + errbuf.toString());
                    return;
                }//if
            } else if (opcion == 0) {
                /**
                 * *************************************************************************
                 * First get a list of devices on this system
                 * ************************************************************************
                 */
                int r = Pcap.findAllDevs(alldevs, errbuf);
                if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    System.err.printf("Can't read list of devices, error is %s", errbuf
                            .toString());
                    return;
                }

                System.out.println("Network devices found:");

                int i = 0;
                for (PcapIf device : alldevs) {
                    String description
                            = (device.getDescription() != null) ? device.getDescription()
                            : "No description available";
                    final byte[] mac = device.getHardwareAddress();
                    String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
                    System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                    List<PcapAddr> direcciones = device.getAddresses();
                    for (PcapAddr direccion : direcciones) {
                        System.out.println(direccion.getAddr().toString());
                    }//foreach

                }//for

                System.out.print("\nEscribe el número de interfaz a utilizar:");
                int interfaz = Integer.parseInt(br.readLine());
                PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
                System.out
                        .printf("\nChoosing '%s' on your behalf:\n",
                                (device.getDescription() != null) ? device.getDescription()
                                : device.getName());

                /**
                 * *************************************************************************
                 * Second we open up the selected device
                 * ************************************************************************
                 */
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */
                int snaplen = 64 * 1024;           // Capture all packets, no trucation
                int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
                int timeout = 10 * 1000;           // 10 seconds in millis

                pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                if (pcap == null) {
                    System.err.printf("Error while opening device for capture: "
                            + errbuf.toString());
                    return;
                }//if

                /**
                 * ******F I L T R O*******
                 */
                PcapBpfProgram filter = new PcapBpfProgram();
                String expression = ""; // "port 80";
                int optimize = 0; // 1 means true, 0 means false
                int netmask = 0;
                int r2 = pcap.compile(filter, expression, optimize, netmask);
                if (r2 != Pcap.OK) {
                    System.out.println("Filter error: " + pcap.getErr());
                }//if
                pcap.setFilter(filter);
                /**
                 * *************
                 */
            }//else if

            /**
             * *************************************************************************
             * Third we create a packet handler which will receive packets from
             * the libpcap loop.
             * ********************************************************************
             */
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                public void nextPacket(PcapPacket packet, String user) {

                    System.out.printf("\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                            new Date(packet.getCaptureHeader().timestampInMillis()),
                            packet.getCaptureHeader().caplen(), // Length actually captured
                            packet.getCaptureHeader().wirelen(), // Original length
                            user // User supplied object
                    );

                    /**
                     * ****Desencapsulado*******
                     */
                    for (int i = 0; i < packet.size(); i++) {
                        System.out.printf("%02X ", packet.getUByte(i));

                        if (i % 16 == 15) {
                            System.out.println("");
                        }
                    }//if

                    int longitud = (packet.getUByte(12) * 256) + packet.getUByte(13);
                    System.out.printf("\nLongitud: %d (%04X)", longitud, longitud);
                    if (longitud < 1500) {
                        System.out.println("--->Trama IEEE802.3");
                        System.out.printf(" |-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X", packet.getUByte(0), packet.getUByte(1), packet.getUByte(2), packet.getUByte(3), packet.getUByte(4), packet.getUByte(5));
                        System.out.printf("\n |-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X", packet.getUByte(6), packet.getUByte(7), packet.getUByte(8), packet.getUByte(9), packet.getUByte(10), packet.getUByte(11));
                        //DSAP
                        //System.out.println(packet.getUByte(15)& 0x00000001);
                        int dsap = packet.getUByte(14) & 0x00000001;
                        String i_g = (dsap == 1) ? "Grupal" : (dsap == 0) ? "Individual" : "Otro";
                        System.out.printf("\n |-->DSAP: %02X   %s", packet.getUByte(14), i_g);

                        //SSAP
                        //System.out.printf("\n |-->DSAP: %02X", packet.getUByte(14));                        
                        int ssap = packet.getUByte(15) & 0x00000001;
                        String c_r = (ssap == 1) ? "Respuesta" : (ssap == 0) ? "Comando" : "Otro";
                        System.out.printf("\n |-->SSAP: %02X   %s", packet.getUByte(15), c_r);

                        //CONTROL
                        if (longitud > 3) {
                            /*Se toman 2 bytes (16 bits) para la parte de control porque es el modo extendido
                            (tamaño maximo de ventana: 127) */
                            System.out.printf("\n |-->Campo de control: %02X %02X", packet.getUByte(16), packet.getUByte(17));
                            //Declaracion y asignacion de los bytes de control a trabajar
                            int primerByte = packet.getUByte(16);
                            int segundoByte = packet.getUByte(17);
                            //Trama de informacion
                            if ((primerByte & 0x00000001) == 0) {
                                System.out.println("\n |-->Tipo: I (Trama de Informacion)");//contienen datos del usuario
                                numeroSecuencia(primerByte, "Extendida");
                                pollFinal(c_r, segundoByte, "Extendida");
                                numeroAcuse(segundoByte, "Extendida");
                            } else if ((primerByte & 0x00000001) == 1) {
                                if (((primerByte >> 1) & 0x00000001) == 0) {
                                    System.out.print("\n |-->Tipo: S (Trama de Supervision)");// confirman la recepción de las tramas I
                                    //Evaluar el tipo de codigo, asi se puede diferenciar el tipo de trama de supervision
                                    int codigo = 0;
                                    codigo = ((primerByte >> 2) & 0x00000011);
                                    switch (codigo) {
                                        case 0:
                                            System.out.print("\n |-->Codigo: Receive Ready (RR)");
                                            pollFinal(c_r, segundoByte, "Extendida");
                                            numeroAcuse(segundoByte, "Extendida");
                                            break;
                                        case 1:
                                            System.out.print(" |-->Codigo: Receive Not Ready (RNR)");
                                            pollFinal(c_r, segundoByte, "Extendida");
                                            numeroAcuse(segundoByte, "Extendida");
                                            break;
                                        case 2:
                                            System.out.print(" |-->Codigo: Reject (REJ)");
                                            pollFinal(c_r, segundoByte, "Extendida");
                                            numeroAcuse(segundoByte, "Extendida");
                                            break;
                                        case 3:
                                            System.out.print(" |-->Codigo: Selective Reject (SREJ)");
                                            pollFinal(c_r, segundoByte, "Extendida");
                                            numeroAcuse(segundoByte, "Extendida");
                                            break;
                                    }
                                }
                            }

                        } else {
                            /*Se toma 1 byte(8 bits) para la parte de control porque es el modo extendido
                            (tamaño maximo de ventana: 7) */
                            System.out.printf("\n |-->Campo de control: %02X   ", packet.getUByte(16));
                            int primerByte = packet.getUByte(16);
                            //Trama de informacion
                            System.out.println(((primerByte >> 1) & 0x00000001));
                            if ((primerByte & 0x00000001) == 0) {
                                System.out.println("\n |-->Tipo: I (Trama de Informacion)");
                                numeroSecuencia(primerByte, "Reducida");
                                pollFinal(c_r, primerByte, "Reducida");
                                numeroAcuse(primerByte, "Reducida");
                            } else if ((primerByte & 0x00000001) == 1) {
                                if (((primerByte >> 1) & 0x00000001) == 0) {
                                    System.out.println(" |-->Tipo: S (Trama de Supervision)");
                                    int codigo = 0;
                                    codigo = ((primerByte >> 2) & 0x000011);
                                    switch (codigo) {
                                        case 0:
                                            System.out.print("\n |-->Codigo: Receive Ready (RR)");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            numeroAcuse(primerByte, "Reducida");
                                            break;
                                        case 1:
                                            System.out.print(" |-->Codigo: Receive Not Ready (RNR)");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            numeroAcuse(primerByte, "Reducida");
                                            break;
                                        case 2:
                                            System.out.print(" |-->Codigo: Reject (REJ)");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            numeroAcuse(primerByte, "Reducida");
                                            break;
                                        case 3:
                                            System.out.print(" |-->Codigo: Selective Reject (SREJ)");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            numeroAcuse(primerByte, "Reducida");
                                            break;
                                    }
                                } else if (((primerByte >> 1) & 0x00000001) == 1) {
                                    System.out.println(" |-->Tipo: U (Trama No Numerada)");
                                    int codigo = reverseBits(primerByte);
                                    //se recorre un espacio para que coincida la mascara con los bits deseados a obtener
                                    int mascaraUno = ((codigo >> 1) & 24);
                                    //System.out.println(Integer.toBinaryString(mascaraUno));
                                    int mascaraDos = ((codigo) & 7);
                                    //System.out.println(Integer.toBinaryString(mascaraDos));
                                    int numeroResultante = mascaraUno + mascaraDos;
                                    //System.out.println(Integer.toBinaryString(numeroResultante));
                                    System.out.println(">> Numero codigo resultante a evaluar: " + numeroResultante);
                                    switch (numeroResultante) {
                                        case 1:
                                            System.out.print("\n |-->Orden: SNRM");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 27:
                                            System.out.print(" |-->Orden: SNRME");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 24:
                                            System.out.print(" |-->Orden: SARM\n |-->Respuesta: DM");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 26:
                                            System.out.print(" |-->Orden: SARME");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 28:
                                            System.out.print(" |-->Orden: SABM");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 30:
                                            System.out.print(" |-->Orden: SABME");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 0:
                                            System.out.print(" |-->Orden: UI\n |-->Respuesta: UI");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 6:
                                            System.out.print(" |-->Respuesta: UA");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 2:
                                            System.out.print(" |-->Orden: DISC\n |-->Respuesta: RD");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 16:
                                            System.out.print(" |-->Orden: SIM\n |-->Respuesta: RIM");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 4:
                                            System.out.print(" |-->Orden: UP");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 25:
                                            System.out.print(" |-->Orden: RSET");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 29:
                                            System.out.print(" |-->Orden: XID\n |-->Respuesta: XID");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                        case 17:
                                            System.out.print(" |-->Respuesta: FRMR");
                                            pollFinal(c_r, primerByte, "Reducida");
                                            break;
                                    }
                                }
                            }
                        }
                    } else if (longitud >= 1500) {
                        System.out.println("-->Trama ETHERNET");
                    }//else

                    //System.out.println("\n\nEncabezado: "+ packet.toHexdump());
                }
            };

            /**
             * *************************************************************************
             * Fourth we enter the loop and tell it to capture 10 packets. The
             * loop method does a mapping of pcap.datalink() DLT value to
             * JProtocol ID, which is needed by JScanner. The scanner scans the
             * packet buffer and decodes the headers. The mapping is done
             * automatically, although a variation on the loop method exists
             * that allows the programmer to sepecify exactly which protocol ID
             * to use as the data link type for this pcap interface.
             * ************************************************************************
             */
            pcap.loop(-1, jpacketHandler, " ");

            /**
             * *************************************************************************
             * Last thing to do is close the pcap handle
             * ************************************************************************
             */
            pcap.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

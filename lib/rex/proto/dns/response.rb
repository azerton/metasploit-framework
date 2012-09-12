####################################
# Created by Daan Raman
# Universiteit Gent, 2011
####################################

require 'rex/proto/dns'
require 'resolv'

module Rex
module Proto
module DNS

###
#
# DNS response class.
###
class Response

	def initialize(request, domain)
		#Query response flag
		request.qr = 1
		#Recursion available flag
		request.ra = 1
		
		self.domain = domain
		self.request = request	
	end
		
	def setData(data)
	  self.data = data
	  
	  #Iterate over all the DNS requests in the query
		self.request.each_question {|name, typeclass|
		tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")
		  
		  if(typeclass.to_s.eql?("Resolv::DNS::Resource::IN::TXT"))
		    self.response = Resolv::DNS::Resource::IN::TXT.new(encode(self.data))	    
      end
      
      if(typeclass.to_s.eql?("Resolv::DNS::Resource::IN::CNAME"))
		    self.response = Resolv::DNS::Resource::IN::CNAME.new(createURLresponse())	    
      end
      
      self.request.add_answer(name, 60, response)
    }
	end
	
	def createURLresponse()
	  return "0." + self.getSeq().to_s + "." + createGarbage().to_s + "." + encode(self.data) + "." + self.domain
	end
	
	def createGarbage()
	  return rand(100);
	end
	
	def encodeResponse()
	  return self.request.encode()
	end
	
	def setType(type)
	  self.type = type
	end
	
	def setSeq(seq)
	  self.seq = seq
	end
	
	def getData()
	  return data
	end
	
	def getType()
	  return type
	end
	
	def getSeq()
	  return seq
	end

#
# Used to store a copy of the original request
#
attr_accessor :request
attr_accessor :response
attr_accessor :data
attr_accessor :type
attr_accessor :seq
attr_accessor :domain

protected

#Returns a string (NetBIOS encoded)
def encode(data)
  	result = ''

  	data.each_byte{|b|
  		result = result + ((b >> 4) + 0x41).chr + ((b & 0xF) + 0x41).chr
  	}	

  	return result
end


#Response
end

#Rex
end
#Proto
end
#DNS
end

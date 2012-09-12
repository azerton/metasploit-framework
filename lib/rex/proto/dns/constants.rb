####################################
# Created by Daan Raman
# Universiteit Gent, 2011
####################################

STAGER = 1
COMMUNICATION = 2

#Size of stage chunks to send over (must fit in TXT record)
#Must be set correctly in the DNS stager too!
#cmp eax, 0x80 - Total number of bytes decoded in stager. 


#Chunk size for sending over reflective DLL to stager
STAGER_CHUNK_SIZE = 100

#Chunk size for sending over payload to DLL
STAGE_CHUNK_SIZE = 16

INJECTING_DLL = true

TYPE_STAGER = "STAGER"
TYPE_STAGE = "DLL"

PAYLOAD_REQUEST = "GETPAYLOAD"
EOF_GET_PAYLOAD = "EOF"

INIT_SESSION = "INITSESSION"
OK_SESSION = "OKSESSION"

POLLING_REQUEST = "GETPOLLING"
POLLING_NO_DATA_ANSWER = "NODATA"

TUNNEL_DATA = "DATA"
TUNNEL_ACK = "ACK"
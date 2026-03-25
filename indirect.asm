extern pebBase : qword

.code

GetMyPeb PROC
	mov rax, gs:[60h]
	mov [pebBase], rax
	ret
GetMyPeb ENDP           

END
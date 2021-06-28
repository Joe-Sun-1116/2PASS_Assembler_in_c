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
	*		�H�U�i���ɮ�Ū�� 
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
	*		�ɮצs������
	*/

	fgets(buffer,64,fSource); // ��Ū�i buffer  
	sscanf(buffer,"%s %s %s",label,mnemonic,operand); // �A�N buffer �������O���O��R�� label, mnemonic, operand 
	
	if(strcmp(mnemonic,"START") == 0){ // �Y�Ĥ@�欰 START 
		locctr = atoi(operand); // operand ���ȳ]���{���}�l����}
		while(locctr > 0){
			
			/*
			*		while �j�餤�N��}�ର16�i�� 
			*/
			
			start += (locctr%10) * pow(16,count);
			locctr /= 10;
			count++;
		} 
		locctr = start;
		fprintf(fIntrm,"%X\t%s\t%s\t%s\n",start,label,mnemonic,operand);
	}
	
	while(!feof(fSource)){  // �}�l�i��Ū�� 
		
		fgets(buffer,64,fSource); // ��Ū�i buffer
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand); // �A�N buffer �������O���O��R�� label, mnemonic, operand...ret�ΨӧP�_���O���X�� 
		
		if(label[0] != '.' && label[0] != ';'){ // ���T�{���O�O�_������ 
			if(ret == 1){ // �Y�u���@�Ӭ� mnemonic 
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%04X\t\t%s\n",locctr,mnemonic);
			}
			else if(ret == 2){ // �Y����Ӭ� mnemonic �� operand 
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%X\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			else if(ret == 3){ // �N�� symbol �b Label field  
				rewind(fSymtab); // �ɮ׫��Ц^��_�l 
				while(!feof(fSymtab)){
					
					/*
					*	�n�T�{ symbol �S������ 
					*/		
							
					flag = 0;
					fscanf(fSymtab,"%s%X",symbol,&address);
					if(strcmp(label,symbol) == 0){
						flag = 1; // �����ƪ� symbol
						printf("\n%s�����ƪ�LABEL,�{���פ�",label);
						return 0; 
					}
				}
				
				if(flag == 0){
					fprintf(fSymtab,"%s\t%X\n",label,locctr);
					fprintf(fIntrm,"%X\t%s\t%s\t%s\n",locctr,label,mnemonic,operand);
				}
			}
			
			rewind(fOpcode); // �}�l�j�M OPtable 
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
					//////////�Y BYTE �ᱵ C'...' �N��p��''��������//////// 
						locctr += len - 3; // -3 ���O�O���� C ' ' 
						flag = 0;
						
						break;
					}
					else if(operand[0] == 'X'){
					////////�Y BYTE �ᱵ X'...' �N��᭱�C��� hex ���׬� 1////////
						if((len-3)%2 != 0) // �Y���_�ƭ� hex 
							locctr += (len-3)/2 + 1;
						else
							locctr += (len-3)/2;
						flag = 0;
						
						break;
					}
				}	
				
				else{	
					flag = 1; // �N��bOPtable���䤣�� 
				}	
			}
			
			if(flag == 1){
				printf("�bOPtable���䤣��%s...",mnemonic);
				printf("\n�{���פ�");
				return 0;
			}
		}
		if(strcmp(mnemonic,"END") == 0){
			break;
		}
	}
	printf("Symbol table ����...\n");
	
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
	*		�H�U�i���ɮ�Ū�� 
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
	*		�ɮ�Ū������ 
	*/
	
	fscanf(fIntrm,"%X%s%s%s",&locctr,label,mnemonic,operand);
	
	if(strcmp(mnemonic,"START") == 0){
		start = (int)strtol(operand,NULL,16);
		fprintf(fobj,"H%s\t%06X%06X",label,start,program_length);
		fprintf(fobj,"\nT%06X00",start);
		
		bseek = ftell(fobj);
		
	}
	fgets(buffer,64,fIntrm); // ���N�Ŧr��Ū�i 
	
	while(!feof(fIntrm)){
		
		fgets(buffer,64,fIntrm); 
		
		ret = sscanf(buffer,"%X%s%s%s",&locctr,label,mnemonic,operand);
		
		/*
		*	�H�U�i�����վ� 
		*/ 
		
		if(ret == 2){ // RSUB
			strcpy(mnemonic,label);	
		}
		
		else if(ret == 3){ // LABEL���� 
			strcpy(operand,mnemonic);
			strcpy(mnemonic,label);
		}
		
		/*
		*	���վ㧹�� 
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

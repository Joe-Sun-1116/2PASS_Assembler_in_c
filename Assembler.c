#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h> 

int PASS1();
//int PASS2();

int main(){
	PASS1();
	//PASS2();
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

	fgets(buffer,64,fSource);
	sscanf(buffer,"%s %s %s",label,mnemonic,operand);
	
	if(strcmp(mnemonic,"START") == 0){
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
	
	while(!feof(fSource)){
		
		fgets(buffer,64,fSource);
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand); // �P�_���O���X�� 
		
		if(label[0] != '.' && label[0] != ';'){ // ���T�{���O�O�_������ 
			if(ret == 1){
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%04X\t\t%s\n",locctr,mnemonic);
			}
			else if(ret == 2){
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%X\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			else if(ret == 3){ // �N�� symbol �b Label field  
				rewind(fSymtab); // �ɮ׫��Ц^��_�l 
				while(!feof(fSymtab)){					
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
			
			rewind(fOpcode);
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
	printf("\nSymbol table ����...\n");
	
	fclose(fSource);
	fclose(fOpcode);
	fclose(fSymtab);
	fclose(fIntrm);
	return 1;
}

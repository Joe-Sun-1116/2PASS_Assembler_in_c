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

	fgets(buffer,64,fSource);
	sscanf(buffer,"%s %s %s",label,mnemonic,operand);
	
	if(strcmp(mnemonic,"START") == 0){
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
	
	while(!feof(fSource)){
		
		fgets(buffer,64,fSource);
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand); // 判斷指令有幾個 
		
		if(label[0] != '.' && label[0] != ';'){ // 先確認指令是否為註解 
			if(ret == 1){
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%04X\t\t%s\n",locctr,mnemonic);
			}
			else if(ret == 2){
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%X\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			else if(ret == 3){ // 代表有 symbol 在 Label field  
				rewind(fSymtab); // 檔案指標回到起始 
				while(!feof(fSymtab)){					
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
	printf("\nSymbol table 完成...\n");
	
	fclose(fSource);
	fclose(fOpcode);
	fclose(fSymtab);
	fclose(fIntrm);
	return 1;
}

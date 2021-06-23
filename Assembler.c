#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PASS1();
//int PASS2();

int main(){
	PASS1();
	//PASS2();
	return 0;
}

int PASS1(){
	FILE *fSource,*fOpcode,*fSymtab,*fIntrm;
	char buffer[64],label[20],mnemonic[8],operand[12];
	int locctr = 0x0,start = 0x0;
	int count = 0,ret = 0;
	
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

	fSymtab = fopen("symble_table.txt","w+");
	
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
		fprintf(fIntrm,"%x\t%s\t%s\t%s\n",start,label,mnemonic,operand);
	}
	
	while(!feof(fSource)){
		fgets(buffer,64,fSource);
		ret = sscanf(buffer,"%s%s%s",label,mnemonic,operand); // 判斷指令有幾個 
		
		if(label[0] != '.' && label[0] != ';'){ // 先確認指令是否為註解 
			if(ret == 1){
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%04x\t\t%s\n",locctr,mnemonic);
			}
			else if(ret == 2){
				strcpy(operand,mnemonic);
				strcpy(mnemonic,label);
				fprintf(fIntrm,"%x\t\t%s\t%s\n",locctr,mnemonic,operand);
			}
			else if(ret == 3){
				
			}
		}
	}
	
}

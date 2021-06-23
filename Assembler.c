#include <stdio.h>
#include <stdlib.h>

int main(){
	int PASS1();
	int PASS2();
	return 0;
}

int PASS1(){
	
	FILE *fSource,*fOpcode,*fSymtab,*fIntrm;
	char buffer[64],label[20],mnemonic[8],operand[12];
	
	
	/****************以下進行檔案存取****************/
	
	fSource = fopen("source.txt", "r");
	if(fSource == NULL){
		printf("Source file open fail!");
		return 0;
	}

	fOpcode = fopen("opcode.txt", "r");
	if(fSource == NULL){
		printf("opcode file open fail!");
		return 0;
	}

	fSymtab = fopen("symble_table.txt","w+");
	
	fIntrm = fopen("Intermediate_file.txt","w");
	
	/****************檔案存取完畢****************/

	fgets(buffer,64,fProg);
	sscanf(buffer,"%s %s %s",label,mnemonic,operand);
	
	if(strcmp(mnemonic), "START" == 0){
		
		
	}
	







}

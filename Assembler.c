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
	int count = 0;
	
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

	fSymtab = fopen("symble_table.txt","w+");
	
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
		fprintf(fIntrm,"%x\t%s\t%s\t%s\n",start,label,mnemonic,operand);
	}
	
	while(!feof(fSource)){
		
	}
	
}

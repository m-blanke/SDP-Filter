#include "sdp-filter.h"

bool str_begins_with(const char* string, const char* prefix){
	while(*prefix){
		if(*prefix++ != *string++){
			return false;
		}
	}
	return true;
}

bool str_ends_with(const char* string, const char* suffix){
	return strcmp(string + (strlen(string) - strlen(suffix)),suffix);
}

bool str_contains(const char* string, const char* infix){
	bool contains = false;;
	for(int i = 0;i < strlen(string);i++){
		if(str_begins_with(string+i,infix)){
			contains = true;
			break;
		}
	}
	return contains;
}


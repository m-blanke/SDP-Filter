#ifndef __SDP_FILTER__CONFIG_H__
#define __SDP_FILTER__CONFIG_H__

/**
*Configuration:
*   BLACKLIST true/false for default policy
*
**/
#define BLACKLIST false
/**
*   VERDICT,"attribute",FILTER,"string"
*   for example:
*   ALLOW,"a=x-plgroup:",BEGINS-WITH,"KaWo1-"
*   VERDICT := ALLOW || DISALLOW
*   FILTER := IS || BEGINS_WITH || ENDS_WITH || CONTAINS
*   
*   RULESC _must_ be the number of rules, or compiler mayhem is going to happen
**/
#define RULESC 3
#define RULES \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Tuerme-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Hilton-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"RWTH"}, \

#endif

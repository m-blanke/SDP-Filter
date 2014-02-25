#ifndef __SDP_FILTER__CONFIG_H__
#define __SDP_FILTER__CONFIG_H__

#define QUEUE 42

#define BLACKLIST false

#define RULESC 3
#define RULES \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Tuerme-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Hilton-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"RWTH"}, \

#endif

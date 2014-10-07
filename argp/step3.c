#include <stdio.h>
#include <argp.h>
static int parse_opt (int key, char *arg,struct argp_state *state){
	switch (key){
		case 'd':{
			unsigned int i;
			for (i = 0; i < atoi (arg); i++)
				printf (".");
			printf ("\n");
			break;
		}
	}
return 0;
}
int main (int argc, char **argv){
	struct argp_option options[] = {
		{ "dot", 'd', "NUM", 0, "Show some dots on the screen"},
		{ 0 }
	};
	struct argp argp = { options, parse_opt, 0, 0 };
	return argp_parse (&argp, argc, argv, 0, 0, 0);
}

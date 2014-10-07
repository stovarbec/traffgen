#include <stdio.h>
#include <argp.h>
static int parse_opt (int key, char *arg, struct argp_state *state){
	int *arg_count = state->input;
	switch (key){
		case 'd':{
			unsigned int i;
			for (i = 0; i < atoi (arg); i++)
				printf (".");
			break;
		}
		case 777:
			return parse_opt ('d', "3", state);
		case ARGP_KEY_ARG:{
			(*arg_count)--;
			if (*arg_count >= 0)
				printf (" %s", arg);
		}
		break;
		case ARGP_KEY_END:{
			printf ("\n");
			if (*arg_count >= 4)
				argp_failure (state, 1, 0, "too few arguments");
			else if (*arg_count < 0)
				argp_failure (state, 1, 0, "too many arguments");
		}
		break;
	}
	return 0;
}

int main (int argc, char **argv){
	struct argp_option options[] ={
		{ "dot", 'd', "NUM", 0, "Show some dots on the screen"},
		{ "ellipsis", 777, 0, 0, "Show an ellipsis on the screen"},
		{ 0 }
	};
	int arg_count = 4;
	struct argp argp = { options, parse_opt, "IP_ADDR" };

	return argp_parse (&argp, argc, argv, 0, 0, &arg_count);
}

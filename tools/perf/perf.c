/*
 * perf.c
 *
 * Performance analysis utility.
 *
 * This is the main hub from which the sub-commands (perf stat,
 * perf top, perf record, perf report, etc.) are started.
 */
#include "builtin.h"

#include "util/env.h"
#include "util/exec_cmd.h"
#include "util/cache.h"
#include "util/quote.h"
#include "util/run-command.h"
#include "util/parse-events.h"
#include "util/parse-options.h"
#include "util/bpf-loader.h"
#include "util/debug.h"
#include <api/fs/tracing_path.h>
#include <pthread.h>

const char perf_usage_string[] =
	"perf [--version] [--help] [OPTIONS] COMMAND [ARGS]";

const char perf_more_info_string[] =
	"See 'perf help COMMAND' for more information on a specific command.";

int use_browser = -1;
static int use_pager = -1;
const char *input_name;

struct cmd_struct {
	const char *cmd;
	int (*fn)(int, const char **, const char *);
	int option;
};

static struct cmd_struct commands[] = {
	{ "buildid-cache", cmd_buildid_cache, 0 },
	{ "buildid-list", cmd_buildid_list, 0 },
	{ "diff",	cmd_diff,	0 },
	{ "evlist",	cmd_evlist,	0 },
	{ "help",	cmd_help,	0 },
	{ "list",	cmd_list,	0 },
	{ "record",	cmd_record,	0 },
	{ "report",	cmd_report,	0 },
	{ "bench",	cmd_bench,	0 },
	{ "stat",	cmd_stat,	0 },
	{ "timechart",	cmd_timechart,	0 },
	{ "top",	cmd_top,	0 },
	{ "annotate",	cmd_annotate,	0 },
	{ "version",	cmd_version,	0 },
	{ "script",	cmd_script,	0 },
	{ "sched",	cmd_sched,	0 },
#ifdef HAVE_LIBELF_SUPPORT
	{ "probe",	cmd_probe,	0 },
#endif
	{ "kmem",	cmd_kmem,	0 },
	{ "lock",	cmd_lock,	0 },
	{ "kvm",	cmd_kvm,	0 },
	{ "test",	cmd_test,	0 },
#ifdef HAVE_LIBAUDIT_SUPPORT
	{ "trace",	cmd_trace,	0 },
#endif
	{ "inject",	cmd_inject,	0 },
	{ "mem",	cmd_mem,	0 },
	{ "data",	cmd_data,	0 },
};

struct pager_config {
	const char *cmd;
	int val;
};

static int pager_command_config(const char *var, const char *value, void *data)
{
	struct pager_config *c = data;
	if (!prefixcmp(var, "pager.") && !strcmp(var + 6, c->cmd))
		c->val = perf_config_bool(var, value);
	return 0;
}

/* returns 0 for "no pager", 1 for "use pager", and -1 for "not specified" */
int check_pager_config(const char *cmd)
{
	struct pager_config c;
	c.cmd = cmd;
	c.val = -1;
	perf_config(pager_command_config, &c);
	return c.val;
}

static int browser_command_config(const char *var, const char *value, void *data)
{
	struct pager_config *c = data;
	if (!prefixcmp(var, "tui.") && !strcmp(var + 4, c->cmd))
		c->val = perf_config_bool(var, value);
	if (!prefixcmp(var, "gtk.") && !strcmp(var + 4, c->cmd))
		c->val = perf_config_bool(var, value) ? 2 : 0;
	return 0;
}

/*
 * returns 0 for "no tui", 1 for "use tui", 2 for "use gtk",
 * and -1 for "not specified"
 */
static int check_browser_config(const char *cmd)
{
	struct pager_config c;
	c.cmd = cmd;
	c.val = -1;
	perf_config(browser_command_config, &c);
	return c.val;
}

static void commit_pager_choice(void)
{
	switch (use_pager) {
	case 0:// 命令行中有--no-pager的时候设置环境变量
		setenv("PERF_PAGER", "cat", 1);
		break;
	case 1:
		/* setup_pager(); */
		break;
	default:
		break;
	}
}

struct option options[] = {
	OPT_ARGUMENT("help", "help"),
	OPT_ARGUMENT("version", "version"),
	OPT_ARGUMENT("exec-path", "exec-path"),
	OPT_ARGUMENT("html-path", "html-path"),
	OPT_ARGUMENT("paginate", "paginate"),
	OPT_ARGUMENT("no-pager", "no-pager"),
	OPT_ARGUMENT("perf-dir", "perf-dir"),
	OPT_ARGUMENT("work-tree", "work-tree"),
	OPT_ARGUMENT("debugfs-dir", "debugfs-dir"),
	OPT_ARGUMENT("buildid-dir", "buildid-dir"),
	OPT_ARGUMENT("list-cmds", "list-cmds"),
	OPT_ARGUMENT("list-opts", "list-opts"),
	OPT_ARGUMENT("debug", "debug"),
	OPT_END()
};

static int handle_options(const char ***argv, int *argc, int *envchanged)
{
  /*
   * 处理参数的函数
   * 接受命令行中去掉perf的剩余参数
   * 例如命令为perf stat ./test 则参数*argv是 stat ./test
   */
	int handled = 0;

	while (*argc > 0) {
		const char *cmd = (*argv)[0];// cmd为perf后的第一个参数 例如stat
		if (cmd[0] != '-')// 不为- 则退出循环
			break;

		/*
		 * For legacy reasons, the "version" and "help"
		 * commands can be written with "--" prepended
		 * to make them look like flags.
		 */
		if (!strcmp(cmd, "--help") || !strcmp(cmd, "--version"))
			break;

		/*
		 * Shortcut for '-h' and '-v' options to invoke help
		 * and version command.
		 */
		if (!strcmp(cmd, "-h")) {
			(*argv)[0] = "--help";// 如果是-h则修改为--help 例如把perf -h命令修改为perf --help
			break;
		}

		if (!strcmp(cmd, "-v")) {
			(*argv)[0] = "--version";// 如果是-v则修改为--version 例如把perf -v命令修改为perf --version
			break;
		}

		/*
		 * Check remaining flags.
		 */
		if (!prefixcmp(cmd, CMD_EXEC_PATH)) {// 如果cmd包含--exec-path 则执行
			cmd += strlen(CMD_EXEC_PATH);// cmd向后移 即忽略掉--exec-path
			if (*cmd == '=')// 如果忽略掉之后的第一个字符为=
				perf_set_argv_exec_path(cmd + 1);
      /* 将--exec-path=后面的部分 传递给函数 函数将参数赋值给全局变量 argv_exec_path 
       * 并设置环境变量PERF_EXEC_PATH为 --exec-path=后面的部分 
       */
			else {
				puts(perf_exec_path());// 处理perf --exec-path命令 返回执行路径
				exit(0);// 进程结束 正常退出进程
			}
		} else if (!strcmp(cmd, "--html-path")) {// 处理perf --html-path命令
			puts(system_path(PERF_HTML_PATH));
			exit(0);
		} else if (!strcmp(cmd, "-p") || !strcmp(cmd, "--paginate")) {
			use_pager = 1;
		} else if (!strcmp(cmd, "--no-pager")) {
			use_pager = 0;
			if (envchanged)
				*envchanged = 1;
		} else if (!strcmp(cmd, "--perf-dir")) {
			if (*argc < 2) {
				fprintf(stderr, "No directory given for --perf-dir.\n");
				usage(perf_usage_string);// 打印并exit
			}
			setenv(PERF_DIR_ENVIRONMENT, (*argv)[1], 1);// 把--perf-dir后面的参数进行环境变量赋值
			if (envchanged)
				*envchanged = 1;
			(*argv)++;// 参数向后移动一个
			(*argc)--;// 参数减一
			handled++;
		} else if (!prefixcmp(cmd, CMD_PERF_DIR)) {// 如果cmd包含 --perf-dir
			setenv(PERF_DIR_ENVIRONMENT, cmd + strlen(CMD_PERF_DIR), 1);//设置环境变量
			if (envchanged)
				*envchanged = 1;
		} else if (!strcmp(cmd, "--work-tree")) {// 如果cmd为 --work-tree
			if (*argc < 2) {
				fprintf(stderr, "No directory given for --work-tree.\n");
				usage(perf_usage_string);
			}
			setenv(PERF_WORK_TREE_ENVIRONMENT, (*argv)[1], 1);
			if (envchanged)
				*envchanged = 1;
			(*argv)++;
			(*argc)--;
      /*
       * 后面几个判断基本相同 处理一种带=的情况 和 一种不带等好的情况
       */
		} else if (!prefixcmp(cmd, CMD_WORK_TREE)) {
			setenv(PERF_WORK_TREE_ENVIRONMENT, cmd + strlen(CMD_WORK_TREE), 1);
			if (envchanged)
				*envchanged = 1;
		} else if (!strcmp(cmd, "--debugfs-dir")) {
			if (*argc < 2) {
				fprintf(stderr, "No directory given for --debugfs-dir.\n");
				usage(perf_usage_string);
			}
			tracing_path_set((*argv)[1]);
			if (envchanged)
				*envchanged = 1;
			(*argv)++;
			(*argc)--;
		} else if (!strcmp(cmd, "--buildid-dir")) {
			if (*argc < 2) {
				fprintf(stderr, "No directory given for --buildid-dir.\n");
				usage(perf_usage_string);
			}
			set_buildid_dir((*argv)[1]);
			if (envchanged)
				*envchanged = 1;
			(*argv)++;
			(*argc)--;
		} else if (!prefixcmp(cmd, CMD_DEBUGFS_DIR)) {
			tracing_path_set(cmd + strlen(CMD_DEBUGFS_DIR));
			fprintf(stderr, "dir: %s\n", tracing_path);
			if (envchanged)
				*envchanged = 1;
		} else if (!strcmp(cmd, "--list-cmds")) {// 处理命令perf --list-cmds
			unsigned int i;

			for (i = 0; i < ARRAY_SIZE(commands); i++) {// 打印commands结构体数组
				struct cmd_struct *p = commands+i;
				printf("%s ", p->cmd);
			}
			putchar('\n');
			exit(0);
		} else if (!strcmp(cmd, "--list-opts")) {// 处理命令
			unsigned int i;

			for (i = 0; i < ARRAY_SIZE(options)-1; i++) {
				struct option *p = options+i;
				printf("--%s ", p->long_name);
			}
			putchar('\n');
			exit(0);
		} else if (!strcmp(cmd, "--debug")) {
			if (*argc < 2) {
				fprintf(stderr, "No variable specified for --debug.\n");
				usage(perf_usage_string);
			}
			if (perf_debug_option((*argv)[1]))
				usage(perf_usage_string);

			(*argv)++;
			(*argc)--;
		} else {
			fprintf(stderr, "Unknown option: %s\n", cmd);
			usage(perf_usage_string);
		}

		(*argv)++;
		(*argc)--;
		handled++;
	}
	return handled;
}

static int handle_alias(int *argcp, const char ***argv)
{
	int envchanged = 0, ret = 0, saved_errno = errno;
	int count, option_count;
	const char **new_argv;
	const char *alias_command;
	char *alias_string;

	alias_command = (*argv)[0];
	alias_string = alias_lookup(alias_command);
	if (alias_string) {
		if (alias_string[0] == '!') {
			if (*argcp > 1) {
				struct strbuf buf;

				strbuf_init(&buf, PATH_MAX);
				strbuf_addstr(&buf, alias_string);
				sq_quote_argv(&buf, (*argv) + 1, PATH_MAX);
				free(alias_string);
				alias_string = buf.buf;
			}
			ret = system(alias_string + 1);
			if (ret >= 0 && WIFEXITED(ret) &&
			    WEXITSTATUS(ret) != 127)
				exit(WEXITSTATUS(ret));
			die("Failed to run '%s' when expanding alias '%s'",
			    alias_string + 1, alias_command);
		}
		count = split_cmdline(alias_string, &new_argv);
		if (count < 0)
			die("Bad alias.%s string", alias_command);
		option_count = handle_options(&new_argv, &count, &envchanged);
		if (envchanged)
			die("alias '%s' changes environment variables\n"
				 "You can use '!perf' in the alias to do this.",
				 alias_command);
		memmove(new_argv - option_count, new_argv,
				count * sizeof(char *));
		new_argv -= option_count;

		if (count < 1)
			die("empty alias for %s", alias_command);

		if (!strcmp(alias_command, new_argv[0]))
			die("recursive alias: %s", alias_command);

		new_argv = realloc(new_argv, sizeof(char *) *
				    (count + *argcp + 1));
		/* insert after command name */
		memcpy(new_argv + count, *argv + 1, sizeof(char *) * *argcp);
		new_argv[count + *argcp] = NULL;

		*argv = new_argv;
		*argcp += count - 1;

		ret = 1;
	}

	errno = saved_errno;

	return ret;
}

const char perf_version_string[] = PERF_VERSION;

#define RUN_SETUP	(1<<0)
#define USE_PAGER	(1<<1)
/*
 * require working tree to be present -- anything uses this needs
 * RUN_SETUP for reading from the configuration file.
 */
#define NEED_WORK_TREE	(1<<2)

static int run_builtin(struct cmd_struct *p, int argc, const char **argv)
{
  /*
   * 比如执行 perf record -e cycles ./test
   * argv 是 record -e cycles ./test
   */
	int status;
	struct stat st;
	const char *prefix;
	char sbuf[STRERR_BUFSIZE];

	prefix = NULL;
	if (p->option & RUN_SETUP)
		prefix = NULL; /* setup_perf_directory(); */

	if (use_browser == -1)
		use_browser = check_browser_config(p->cmd);

	if (use_pager == -1 && p->option & RUN_SETUP)
		use_pager = check_pager_config(p->cmd);
	if (use_pager == -1 && p->option & USE_PAGER)
		use_pager = 1;
	commit_pager_choice();// 根据pager选项设置环境变量 具体见函数内部的注释

	status = p->fn(argc, argv, prefix);// 最关键的一个函数 通过函数指针调用相应的cmd_xxx函数
	exit_browser(status);
	perf_env__exit(&perf_env);
	bpf__clear();

	if (status)
		return status & 0xff;

	/* Somebody closed stdout? */
	if (fstat(fileno(stdout), &st))
		return 0;
	/* Ignore write errors for pipes and sockets.. */
	if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))
		return 0;

	status = 1;
	/* Check for ENOSPC and EIO errors.. */
	if (fflush(stdout)) {
		fprintf(stderr, "write failure on standard output: %s",
			strerror_r(errno, sbuf, sizeof(sbuf)));
		goto out;
	}
	if (ferror(stdout)) {
		fprintf(stderr, "unknown write failure on standard output");
		goto out;
	}
	if (fclose(stdout)) {
		fprintf(stderr, "close failed on standard output: %s",
			strerror_r(errno, sbuf, sizeof(sbuf)));
		goto out;
	}
	status = 0;
out:
	return status;
}

static void handle_internal_command(int argc, const char **argv)// 最关键的函数run_builtin
{
	const char *cmd = argv[0];
	unsigned int i;
	static const char ext[] = STRIP_EXTENSION; // 常量的初始化值为"" ext表示后缀

	if (sizeof(ext) > 1) {// 如果有后缀 则去掉argv[0]的后缀ext
		i = strlen(argv[0]) - strlen(ext);
		if (i > 0 && !strcmp(argv[0] + i, ext)) {
			char *argv0 = strdup(argv[0]);
			argv[0] = cmd = argv0;
			argv0[i] = '\0';
		}
	}

	/* Turn "perf cmd --help" into "perf help cmd" */
	if (argc > 1 && !strcmp(argv[1], "--help")) {
		argv[1] = argv[0];
		argv[0] = cmd = "help";
	}

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		struct cmd_struct *p = commands+i;
		if (strcmp(p->cmd, cmd))
			continue;
		exit(run_builtin(p, argc, argv));// run_builtin调用builtin-xxx.c中的cmd_xxx函数
	}
}

static void execv_dashed_external(const char **argv)
{
	struct strbuf cmd = STRBUF_INIT;
	const char *tmp;
	int status;

	strbuf_addf(&cmd, "perf-%s", argv[0]);

	/*
	 * argv[0] must be the perf command, but the argv array
	 * belongs to the caller, and may be reused in
	 * subsequent loop iterations. Save argv[0] and
	 * restore it on error.
	 */
	tmp = argv[0];
	argv[0] = cmd.buf;

	/*
	 * if we fail because the command is not found, it is
	 * OK to return. Otherwise, we just pass along the status code.
	 */
	status = run_command_v_opt(argv, 0);
	if (status != -ERR_RUN_COMMAND_EXEC) {
		if (IS_RUN_COMMAND_ERR(status))
			die("unable to run '%s'", argv[0]);
		exit(-status);
	}
	errno = ENOENT; /* as if we called execvp */

	argv[0] = tmp;

	strbuf_release(&cmd);
}

static int run_argv(int *argcp, const char ***argv)
{
	int done_alias = 0;

	while (1) {
		/* See if it's an internal command */
		handle_internal_command(*argcp, *argv);

		/* .. then try the external ones */
		execv_dashed_external(*argv);

		/* It could be an alias -- this works around the insanity
		 * of overriding "perf log" with "perf show" by having
		 * alias.log = show
		 */
		if (done_alias || !handle_alias(argcp, argv))
			break;
		done_alias = 1;
	}

	return done_alias;
}

static void pthread__block_sigwinch(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGWINCH);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
}

void pthread__unblock_sigwinch(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGWINCH);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

int main(int argc, const char **argv)
  /*
   * 处理执行perf相关命令的入口函数
   * 如果想修改perf只需要 先在源代码中修改 然后make && make install
   */
{
	const char *cmd;
	char sbuf[STRERR_BUFSIZE];

	/* The page_size is placed in util object. */
	page_size = sysconf(_SC_PAGE_SIZE);// sysconf 系统调用 获取配置信息
	cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);

	cmd = perf_extract_argv0_path(argv[0]);
  /*
   * 例如输入命令 /home/hougq/perf stat ./test
   * cmd变为perf stat ./test
   * 路径/home/hougq存入全局变量argv0_path中
   */
	if (!cmd)
		cmd = "perf-help";

	/* get debugfs/tracefs mount point from /proc/mounts */
	tracing_path_mount();// 获取挂载点 然后分别存入到3个字符数组中

	/*
	 * "perf-xxxx" is the same as "perf xxxx", but we obviously:
	 *
	 *  - cannot take flags in between the "perf" and the "xxxx".
	 *  - cannot execute it externally (since it would just do
	 *    the same thing over again)
	 *
	 * So we just directly call the internal command handler, and
	 * die if that one cannot handle it.
	 */
	if (!prefixcmp(cmd, "perf-")) {// 如果cmd中包含前缀"perf-"
		cmd += 5;
		argv[0] = cmd;// cmd去掉前缀"perf-"
		handle_internal_command(argc, argv);
		fprintf(stderr, "cannot handle %s internally", cmd);
		goto out;
	}
	if (!prefixcmp(cmd, "trace")) {// 如果cmd中包含前缀"trace"
#ifdef HAVE_LIBAUDIT_SUPPORT
		set_buildid_dir(NULL);
		setup_path();
		argv[0] = "trace";
		return cmd_trace(argc, argv, NULL);
#else
		fprintf(stderr,
			"trace command not available: missing audit-libs devel package at build time.\n");
		goto out;
#endif
	}
	/* Look for flags.. */
	argv++;// 向后移动一个参数 例如perf stat ./test argv指向stat
	argc--;// 参数数量-1
	handle_options(&argv, &argc, NULL);// 处理命令行参数 有一些可以直接结束perf进程
	commit_pager_choice();// 在handle_options函数中处理过page相关的全局变量use_pager 设置为0或1 未设置则默认值为-1
	set_buildid_dir(NULL);

	if (argc > 0) {
		if (!prefixcmp(argv[0], "--"))// argv[0] 去掉前缀--
			argv[0] += 2;
	} else {// 相当于只执行perf命令 没有任何参数
		/* The user didn't specify a command; give them help */
		printf("\n usage: %s\n\n", perf_usage_string);
		list_common_cmds_help();
		printf("\n %s\n\n", perf_more_info_string);
		goto out;
	}
	cmd = argv[0];// cmd 变为argv[0]去掉前缀--(如果有前缀--的话)

	test_attr__init();// 获取常量PERF_TEST_ATTR 如果有常量则 test_attr__enabled 为true

	/*
	 * We use PATH to find perf commands, but we prepend some higher
	 * precedence paths: the "--exec-path" option, the PERF_EXEC_PATH
	 * environment, and the $(perfexecdir) from the Makefile at build
	 * time.
	 */
	setup_path();
	/*
	 * Block SIGWINCH notifications so that the thread that wants it can
	 * unblock and get syscalls like select interrupted instead of waiting
	 * forever while the signal goes to some other non interested thread.
	 */
	pthread__block_sigwinch();

	while (1) {
		static int done_help;
		int was_alias = run_argv(&argc, &argv);

		if (errno != ENOENT)
			break;

		if (was_alias) {
			fprintf(stderr, "Expansion of alias '%s' failed; "
				"'%s' is not a perf-command\n",
				cmd, argv[0]);
			goto out;
		}
		if (!done_help) {
			cmd = argv[0] = help_unknown_cmd(cmd);
			done_help = 1;
		} else
			break;
	}

	fprintf(stderr, "Failed to run command '%s': %s\n",
		cmd, strerror_r(errno, sbuf, sizeof(sbuf)));
out:
	return 1;
}

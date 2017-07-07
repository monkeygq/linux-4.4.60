#include "cache.h"
#include "exec_cmd.h"
#include "quote.h"

#include <string.h>

#define MAX_ARGS	32

static const char *argv_exec_path;
static const char *argv0_path;

const char *system_path(const char *path)
{
	static const char *prefix = PREFIX;
	struct strbuf d = STRBUF_INIT;

	if (is_absolute_path(path))
		return path;

	strbuf_addf(&d, "%s/%s", prefix, path);
	path = strbuf_detach(&d, NULL);
	return path;
}

const char *perf_extract_argv0_path(const char *argv0)
{
	const char *slash;

	if (!argv0 || !*argv0)
		return NULL;
	slash = argv0 + strlen(argv0);// slash 指向argv0的\0位置

	while (argv0 <= slash && !is_dir_sep(*slash))// argv0 <=slash 并且 *slash不为/
		slash--;

	if (slash >= argv0) {// 在argv0指向的字符串中找到了/
		argv0_path = strndup(argv0, slash - argv0);// 复制/前边的字符串到全局变量argv0_path中
		return argv0_path ? slash + 1 : NULL;// 返回/后边的字符串部分
	}

	return argv0;// argv0中不包含/ 则返回本身
    /*  
     * 例如输入命令 /home/hougq/perf stat ./test
     * cmd变为perf stat ./test
     * 路径/home/hougq存入全局变量argv0_path中
     */

}

void perf_set_argv_exec_path(const char *exec_path)
{
	argv_exec_path = exec_path;// 设置全局变量
	/*
	 * Propagate this setting to external programs.
	 */
	setenv(EXEC_PATH_ENVIRONMENT, exec_path, 1);
  /*
   * 设置环境变量PERF_EXEC_PATH为exec_path
   * setenv的第三个参数overwrite 
   *   如果不为0 则覆盖掉要设置的环境变量
   *   如果为0 如果原来环境变量被设置过 则忽略这次setenv的设置 
   */
}


/* Returns the highest-priority, location to look for perf programs. */
const char *perf_exec_path(void)
{
	const char *env;

	if (argv_exec_path)
		return argv_exec_path;

	env = getenv(EXEC_PATH_ENVIRONMENT);
	if (env && *env) {
		return env;
	}

	return system_path(PERF_EXEC_PATH);
}

static void add_path(struct strbuf *out, const char *path)
{
	if (path && *path) {
		if (is_absolute_path(path))
			strbuf_addstr(out, path);
		else
			strbuf_addstr(out, make_nonrelative_path(path));

		strbuf_addch(out, PATH_SEP);
	}
}

void setup_path(void)
{
	const char *old_path = getenv("PATH");
	struct strbuf new_path = STRBUF_INIT;

	add_path(&new_path, perf_exec_path());
	add_path(&new_path, argv0_path);

	if (old_path)
		strbuf_addstr(&new_path, old_path);
	else
		strbuf_addstr(&new_path, "/usr/local/bin:/usr/bin:/bin");

	setenv("PATH", new_path.buf, 1);

	strbuf_release(&new_path);
}

static const char **prepare_perf_cmd(const char **argv)
{
	int argc;
	const char **nargv;

	for (argc = 0; argv[argc]; argc++)
		; /* just counting */
	nargv = malloc(sizeof(*nargv) * (argc + 2));

	nargv[0] = "perf";
	for (argc = 0; argv[argc]; argc++)
		nargv[argc + 1] = argv[argc];
	nargv[argc + 1] = NULL;
	return nargv;
}

int execv_perf_cmd(const char **argv) {
	const char **nargv = prepare_perf_cmd(argv);

	/* execvp() can only ever return if it fails */
	execvp("perf", (char **)nargv);

	free(nargv);
	return -1;
}


int execl_perf_cmd(const char *cmd,...)
{
	int argc;
	const char *argv[MAX_ARGS + 1];
	const char *arg;
	va_list param;

	va_start(param, cmd);
	argv[0] = cmd;
	argc = 1;
	while (argc < MAX_ARGS) {
		arg = argv[argc++] = va_arg(param, char *);
		if (!arg)
			break;
	}
	va_end(param);
	if (MAX_ARGS <= argc)
		return error("too many args to run %s", cmd);

	argv[argc] = NULL;
	return execv_perf_cmd(argv);
}

/*
 * Copyright (c) 2024 SUSE LLC
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

/*
 * apk2solv - create a solv file from multiple apk packages
 * 
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "pool.h"
#include "repo.h"
#include "repo_apk.h"
#include "repo_solv.h"
#include "solv_xfopen.h"
#include "common_write.h"

static char *
fgets0(char *s, int size, FILE *stream)
{
  char *p = s;
  int c;

  while (--size > 0)
    {
      c = getc(stream);
      if (c == EOF)
	{
	  if (p == s)
	    return 0;
	  c = 0;
	}
      *p++ = c;
      if (!c)
	return s;
    }
  *p = 0;
  return s;
}

int
main(int argc, char **argv)
{
  const char **pkgs = 0;
  char *manifest = 0;
  int manifest0 = 0;
  int isrepo = 0;
  int islocaldb = 0;
  int i, c, res, npkgs = 0;
  Pool *pool = pool_create();
  Repo *repo;
  FILE *fp;
  char buf[4096], *p;
  int flags = 0;

  while ((c = getopt(argc, argv, "0:m:iCrl")) >= 0)
    {
      switch(c)
	{
	case 'm':
	  manifest = optarg;
	  break;
	case '0':
	  manifest0 = 1;
	  break;
	case 'r':
	  isrepo = 1;
	  break;
	case 'l':
	  islocaldb = 1;
	  isrepo = 1;
	  break;
	case 'i':
	  flags |= APK_ADD_WITH_PKGID;
	  break;
	case 'C':
	  flags |= APK_ADD_WITH_HDRID;
	  break;
	default:
	  exit(1);
	}
    }
  if (manifest)
    {
      if (!strcmp(manifest, "-"))
        fp = stdin;
      else if ((fp = fopen(manifest, "r")) == 0)
	{
	  perror(manifest);
	  exit(1);
	}
      for (;;)
	{
	  if (manifest0)
	    {
	      if (!fgets0(buf, sizeof(buf), fp))
		break;
	    }
	  else
	    {
	      if (!fgets(buf, sizeof(buf), fp))
		break;
	      if ((p = strchr(buf, '\n')) != 0)
		*p = 0;
	    }
          pkgs = solv_extend(pkgs, npkgs, 1, sizeof(char *), 15);
	  pkgs[npkgs++] = strdup(buf);
	}
      if (fp != stdin)
        fclose(fp);
    }
  while (optind < argc)
    {
      pkgs = solv_extend(pkgs, npkgs, 1, sizeof(char *), 15);
      pkgs[npkgs++] = solv_strdup(argv[optind++]);
    }
  repo = repo_create(pool, "apk2solv");
  repo_add_repodata(repo, 0);
  res = 0;
  if (isrepo)
    {
      if (islocaldb)
	flags |= APK_ADD_INSTALLED_DB;
      if (!npkgs)
	{
	  if (repo_add_apk_repo(repo, stdin, REPO_REUSE_REPODATA|REPO_NO_INTERNALIZE|flags) != 0)
	    {
	      fprintf(stderr, "apk2solv: %s\n", pool_errstr(pool));
	      res = 1;
	    }
	}
      else 
	{
	  for (i = 0; i < npkgs; i++)
	    {
	      FILE *fp;
	      if (!(fp = fopen(pkgs[i], "r")))
		{
		  perror(pkgs[i]);
		  res = 1;
		}
	      else
		{
		  if (repo_add_apk_repo(repo, fp, REPO_REUSE_REPODATA|REPO_NO_INTERNALIZE|flags) != 0)
		    {
		      fprintf(stderr, "apk2solv: %s\n", pool_errstr(pool));
		      res = 1;
		    }
		  fclose(fp);
		}
	    }
	}
    }
  else
    {
      for (i = 0; i < npkgs; i++)
	if (repo_add_apk_pkg(repo, pkgs[i], REPO_REUSE_REPODATA|REPO_NO_INTERNALIZE|flags) == 0)
	  {
	    fprintf(stderr, "apk2solv: %s\n", pool_errstr(pool));
	    res = 1;
	  }
    }
  repo_internalize(repo);
  tool_write(repo, stdout);
  pool_free(pool);
  for (c = 0; c < npkgs; c++)
    solv_free((char *)pkgs[c]);
  solv_free(pkgs);
  exit(res);
}


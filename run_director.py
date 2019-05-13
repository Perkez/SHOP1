import os, sys, subprocess, argparse, re, datetime, time, uuid
import billingutil, genlib
from dbutil.connections import get_adminreports_conn

parser = argparse.ArgumentParser(description = 'Run the Director')
parser.add_argument('-c', help = 'log to console instead of the configured files',
							action = 'store_true', default = False)
parser.add_argument('-f', help = 'freqId to run; if not specified, all active FreqIds will be run',
						type = int, metavar = 'FREQID')
parser.add_argument('-d', help = 'data date to request (start); format is YYYY-MM-DD',
						type = str, metavar = 'START_DATE')
parser.add_argument('-e', help = 'data date to request (end); format is YYYY-MM-DD',
						type = str, metavar = 'END_DATE')
parser.add_argument('-i', help = 'keep running, every INTERVAL seconds',
						type = int, metavar = 'INTERVAL')
parser.add_argument('-r', help = "Don't produce any output on stdout other than the DIRECTOR_RUN_ID.", 
								action = 'store_true',
								default = False)
parser.add_argument('-w', help = "Set WAIT_FOR_KILL to 1 in the launched process's environment. Useful for debugging and testing.", 
								action = 'store_true',
								default = False)
parser.add_argument('-u', help = "Override the DIRRUNID.", type = int)
parser.add_argument('-t', help = "Each day should be run T times.", type = int, default = 1)
parser.add_argument('-m', help = "Clear the billing data for the indicated interval before running.", 
																					action = 'store_true')
								
args = parser.parse_args()

if args.e is not None and args.d is None:
	raise Exception('-e should be specified only toghether with -d')

DIRECTOR_LOG_PATH = billingutil.get_conf_dict()['DIRECTOR_LOG_PATH']
# DIRECTOR_PACKAGE_PATH = billingutil.get_conf_dict()['DIRECTOR_PACKAGE_PATH']
LAST_DAYS_TO_DOWNLOAD_WHEN_NO_DATE_IS_SPECIFIED = 5

if args.f is not None:
	os.environ['BILLING_DIRECTOR_FREQID_TO_RUN'] = str(args.f)
else:
	os.environ['BILLING_DIRECTOR_FREQID_TO_RUN'] = ''

if args.w:
	os.environ['WAIT_FOR_KILL'] = '1'

for string in [args.d, args.e]:
	if string is not None:
		if not re.match(r'^\d{4,4}-\d{2,2}-\d{2,2}$', string):
			raise ValueError('Invalid Date format. Format should be YYYY-MM-DD')

if args.m:
	if args.f is None or args.d is None or args.e is None:
		raise Exception('-m should be specified only together with -f, -d and -e')
	cline = [
		sys.executable,
		'-tt',
		'-m',
		'billing.scripts.clear_adminreports_data',
		str(args.f),
		args.d,
		args.e,
	]
	retcode = subprocess.call(cline)
	if retcode != 0:
		raise Exception('Received exit code %s from clear_adminreports_data script.' % retcode)


if args.d is not None:
	dates_to_run = [ ]
	if args.e is None:
		args.e = args.d
	current_date = genlib.parse_date_YYYY_MM_DD(args.d)
	end_date = genlib.parse_date_YYYY_MM_DD(args.e)
	while end_date >= current_date:
		dates_to_run.append(current_date)
		current_date += datetime.timedelta(days = 1)
else:
	dates_to_run = [None]



exit_codes = [ ]

for repi in xrange(args.t):
	while True:
		time_last_call = time.time()
		for date_to_run in dates_to_run:
			if date_to_run is not None:
				to_set = genlib.date_to_YYYY_MM_DD(date_to_run)
				if not args.r:
					print ('Running for date: %s' % to_set),
				os.environ['DATA_DATE'] = to_set
			with get_adminreports_conn() as ar_conn:
				if args.u is None:
					dirrunid = str(ar_conn.execute('select DIRECTORUNSSEQ.nextval from dual').fetchone()[0])
				else:
					dirrunid = str(args.u)
			path = os.path.join(DIRECTOR_LOG_PATH, 'director_' + dirrunid)
			with open(path + '.out', 'w') as stdout_f, \
				 open(path + '.err', 'w') as stderr_f:
					
						os.environ['DIRECTOR_RUN_ID'] = dirrunid

						if args.r:
							print os.environ['DIRECTOR_RUN_ID'],
						else:
							print 'Launching new director process with DIRECTOR_RUN_ID:', os.environ['DIRECTOR_RUN_ID'],
						exit_code = subprocess.call(
							[
								### 'dtexec',
								### '/Reporting', 'V',
								### '/File', DIRECTOR_PACKAGE_PATH,
								sys.executable,
								'-m',
								'billing.run_python',
								'--',
								'NONE',
								'billing.scripts.adminreports_director',
							],
							stdout = stdout_f if not args.c else None,
							stderr = stderr_f if not args.c else None,
							env = os.environ,
						)

						if not args.r:
							print 'Got exit code:', exit_code,

						exit_codes.append(exit_code)
			print
		if not args.i:
			break
		else:
			while True:
				if time.time() - time_last_call < args.i:
					time.sleep(.1)
				else:
					break

sys.exit(max(exit_codes) if len(exit_codes) > 0 else 2)

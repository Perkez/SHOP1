import os, logging, re, sys
import datetime, threading, platform, urllib, time, subprocess
import billingutil, genlib
import datetime
from dbutil.connections import get_adminreports_conn

LOGGER = logging.getLogger()

TODAY = "TODAY"
YESTERDAY = "YESTERDAY"
TOMORROW = "TOMORROW"

DIRECTOR_RUN_ID = "DIRECTOR_RUN_ID"

FIRST_DAY_LAST_MONTH = "FIRST_DAY_LAST_MONTH"
LAST_DAY_LAST_MONTH = "LAST_DAY_LAST_MONTH"

CURRENT_TIMESTAMP = "CURRENT_TIMESTAMP"
	
BILLING_DIRECTOR_FREQID_TO_RUN = "BILLING_DIRECTOR_FREQID_TO_RUN"
WAIT_FOR_KILL = "WAIT_FOR_KILL"
DATA_DATE = "DATA_DATE"
NEXT_DATA_DATE = "NEXT_DATA_DATE"
CURRENT_DATE = "CURRENT_DATE"
PROG_MONTHLY_DATE = "PROG_MONTHLY_DATE"
DATA_DATE_ONLY_NUMBERS = "DATA_DATE_ONLY_NUMBERS"
DATA_DATE_ONLY_NUMBERS_YEAR_MONTH = "DATA_DATE_ONLY_NUMBERS_YEAR_MONTH"
DATA_DATE_YEAR = "DATA_DATE_YEAR"
DATA_DATE_MONTH = "DATA_DATE_MONTH"
DATA_DATE_DAY = "DATA_DATE_DAY"
DATA_DATE_END_MONTH = "DATA_DATE_END_MONTH"
FREQ = "FREQ"
FREQID = "FREQID"
FR_NAME = "FR_NAME"
DSR_ID = "DSR_ID"
SOURCE_OUT = "SOURCE_OUT"
RETRIEVE_PATH = "RETRIEVE_PATH"
USERNAME = "USERNAME"
PASSWORD = "PASSWORD"
USERNAME_URL_ENC = "USERNAME_URL_ENC"
PASSWORD_URL_ENC = "PASSWORD_URL_ENC"    
DATA_DATE_PREVIOUS_MONTH_YEAR = "DATA_DATE_PREVIOUS_MONTH_YEAR"
DATA_DATE_PREVIOUS_MONTH_MONTH =  "DATA_DATE_PREVIOUS_MONTH_MONTH"

PHASE = "PHASE"
PHASE_DOWNLOAD = "D"
PHASE_UPLOAD = "U"

SKIPPED_DUE_TO_NOT_FIRST_DAY_OF_MONTH = "SNFDM"
SKIPPED_DUE_TO_SAFEDAY_NOT_REACHED = "SSDNR"
SKIPPED_DUE_TO_FINAL_PHASE_SUCCESSFULLY_COMPLETED = "SFPSC"
SKIPPED_DUE_TO_PAST_PASSW_FAILURE = "SPPF"
SKIPPED_DUE_TO_MAX_TRIES_REACHED = "SMTR"
SKIPPED_DUE_TO_RUNNING_ALREADY = "SRA"
SKIPPED_DUE_TO_SUCCESS_ALREADY = "SSA"
SKIPPED_DUE_TO_MAX_PROCESSES_LAUNCHED_REACHED = "SMPLR"
SKIPPED_DUE_TO_NOT_ALL_DOWNLOADS_DONE = "SNADD"
SKIP_DUE_TO_DATADATEENDMONTH_GE_TO_LOGICAL_DATE = "SDGLD"
LAUNCHED_PROCESS = "LP"
SKIPPED_DUE_TIME_NOT_YET_REACHED = "STNYR"
ERROR_DURING_PASSWORD_DECRYPT = "EDPD"
MEDIATION_BILLING_TEST_OVERRIDE_SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE = \
				'MEDIATION_BILLING_TEST_OVERRIDE_SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE'

LOG_DATE_IN_FUTURE = "LOGICAL_DATE_IN_FUTURE"

MAX_PROCESSES_TO_LAUNCH = None

MAX_CONCURRENT_PROCESSES = None

SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE = None

PHASE_SEQUENCE = [ PHASE_DOWNLOAD, PHASE_UPLOAD ]

mainTrans = None

WRONG_USERNAME_OR_PASSWORD_EXIT_CODE = 99
NOT_A_CSV_EXIT_CODE = 98

LOG_TO_DB = True

configFilePath = None
configDoc = None;
dataSourceRunsLogPath = None
dataDatePassedStr = None
retrievedPath = None

processSemaphore = None


def parseDefs(defs):
	if defs is not None:
		defs = defs.strip()

	if defs:
		definitionsSplit = re.split(r"\s*[\r\n]+\s*", defs)
	else:
		definitionsSplit = [ ]

	variables = { }
	variables[CURRENT_TIMESTAMP] = genlib.datetime_to_filename_safe(datetime.datetime.now())

	for stringContainingEquals in definitionsSplit:
		LOGGER.info('Definition found after splitting by whitespace: %s', stringContainingEquals)

		nameValuePair = stringContainingEquals.split('=', 1)

		if len(nameValuePair) == 2:
			variables[nameValuePair[0]] = nameValuePair[1]
		else:
			variables[nameValuePair[0]] = ''

	return variables

def lockFreqid(conn, freqid):
	# This FOR UPDATE NOWAIT query is not done with the intention to update
	# anything in this table, but it will still lock the DataSourceFreq row so
	# that any other instances of this class will not run concurrently. If
	# another instance is launched it will receive an "ORA-00054 resource busy
	# and NOWAIT specified" error here and skip to the exception.  
	# handler, i.e. it will move to the next DataSourceFreq record.

	sql = "select * from DataSourceFreq where id = :1 FOR UPDATE NOWAIT"
	conn.execute(sql, [freqid])
	LOGGER.info("Successfully locked DataSourceFreq record with id: %s", freqid)

def updateDataSourceFreq(conn_autocommit, actionTaken, dsrId, dsrFreqId):
	sql =  """
			update datasourcefreqruns set actiontaken = :1, dsrid = :2, updatedat = current_timestamp 
			where id = :3
	"""
	conn_autocommit.execute(sql, [actionTaken, dsrId, dsrFreqId])

def main():
	global processSemaphore

	LOGGER.info('Starting adminreports_director.')

	dataSourceRunsLogPath = billingutil.get_conf_dict()['DATASOURCERUNS_LOG_PATH']
	retrievedPath = billingutil.get_conf_dict()['DATARETR_RETRIEVED_PATH']
	dirRunId = os.environ['DIRECTOR_RUN_ID']

	launchedThreads = [ ]

	LOGGER.info('dirRunId: %s', dirRunId)

	MAX_PROCESSES_TO_LAUNCH = int(billingutil.get_conf_dict()['MAX_PROCESSES_TO_LAUNCH'])
	MAX_CONCURRENT_PROCESSES = int(billingutil.get_conf_dict()['MAX_CONCURRENT_PROCESSES'])
	SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE = billingutil.get_conf_dict().get('SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE') == '1'

	LOGGER.info('dataSourceRunsLogPath: %s', dataSourceRunsLogPath)
	LOGGER.info('retrievedPath: %s', retrievedPath)
	LOGGER.info('MAX_PROCESSES_TO_LAUNCH: %s', MAX_PROCESSES_TO_LAUNCH)
	LOGGER.info('MAX_CONCURRENT_PROCESSES: %s', MAX_CONCURRENT_PROCESSES)
	LOGGER.info('SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE: %s', SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE)


	processSemaphore = threading.Semaphore(MAX_CONCURRENT_PROCESSES)

	dirRunErrorCode = None

	with get_adminreports_conn() as adminreports_conn, \
							get_adminreports_conn() as adminreports_conn_autocommit:
		adminreports_conn_autocommit.dbapi_conn.autocommit = 1

		logicalDate = genlib.trunc(
			adminreports_conn.execute("select ld from logicaldates where id = 2").fetchone()[0]
		)

		dataDatePassedStr = os.environ.get('DATA_DATE')

		LOGGER.info('logicalDate: %s', logicalDate)

		# Translation of the PreExecute() function.

		sql = "insert into DIRECTORRUNS (ID, STARTEDAT) VALUES (:1, CURRENT_TIMESTAMP)"
		adminreports_conn_autocommit.execute(sql, [dirRunId])

		currentDateTime = datetime.datetime.now()
		logicalHours = currentDateTime.hour
		logicalMinutes = currentDateTime.minute

		LOGGER.info('currentDateTime: %s', currentDateTime)
		LOGGER.info('logicalHours: %s', logicalHours)
		LOGGER.info('logicalMinutes: %s', logicalMinutes)

		# End of translation of the PreExecute() function.


		# Translation of the CreateNewOutputRows() function.

		processesLaunched = 0
		freqQuery = '''
             select 
             fr.id as frid,
             fr.freq,
             ds.name as dsname,
             null,
             GenerateScriptCLI,
             null,
             null,
             fr.name as frname,
             maxtries,
             so.code,
             so.code,
             so.username,
             so.enc_password,
             fr.safetime,
             ds.filesuffix,
			 fr.safeday
             from 
             DataSourceFreq         fr
             join Reports       ds  on ds.id = fr.reportid
             join Admins   so  on so.id = fr.adminid
             where (ds.isactive = 1 and fr.isactive = 1 and :1 is null)
             or
             (fr.id = :2)
             order by fr.id
		'''

		try:
			freqIdToRun = os.environ.get(BILLING_DIRECTOR_FREQID_TO_RUN)
			LOGGER.info('Received BILLING_DIRECTOR_FREQID_TO_RUN: %s', freqIdToRun)

			reader = adminreports_conn.execute(freqQuery, [ freqIdToRun, freqIdToRun ])

			for reader_row in reader:

				try:

					LOGGER.info('Now handling reader_row: %s', reader_row)

					freqid = reader_row[0]
					freq = reader_row[1]
					dsname = reader_row[2]
					soCode = reader_row[10]
					soUsername = reader_row[11]
					soEncPassword = reader_row[12]
					safeTime = reader_row[13]
					safeDay = reader_row[15]
					fileSuffix = reader_row[14]
					frname = reader_row[7]
					maxTries = reader_row[8]
					generateScriptCLI = reader_row[4]
					sourceOut = reader_row[9]

					if logicalDate > datetime.date.today():
						msg = "logicalDate configured (%s) is larger than the system date. This is not allowed for data integrity reasons." % logicalDate
						dirRunErrorCode = LOG_DATE_IN_FUTURE
						raise Exception(msg)

					freqrunid_sql = "select FREQRUNSSEQ.nextval from dual"

					freqRunId = adminreports_conn.execute(freqrunid_sql).fetchone()[0]

					LOGGER.info('freq: %s', freq)
					LOGGER.info('freqRunId: %s', freqRunId)
					LOGGER.info('Handling freqid: %s, soCode: %s', freqid, soCode)

					lockFreqid(adminreports_conn, freqid)

					LOGGER.info('Director is processing frid: %s', freqid)
					
					##Special case
					##For progressive balance monthly, we take only the 1st day of current month
					##instead of whole last month (1st to last day)
					prog_date = datetime.date.today()

					if dataDatePassedStr is not None:
						dataDate = genlib.trunc(genlib.parse_date_YYYY_MM_DD(dataDatePassedStr))
						prog_date = genlib.trunc(genlib.parse_date_YYYY_MM_DD(dataDatePassedStr))
					else:
						if freq == 'D':
							dataDate = genlib.trunc(logicalDate + datetime.timedelta(days = -1))
						elif freq == 'M':
							if logicalDate.month == 1 :
								dataDate = datetime.date(
									logicalDate.year - 1,
									logicalDate.month - 1 or 12,
									1
								)
							else :
								dataDate = datetime.date(
									logicalDate.year,
									logicalDate.month - 1 or 12,
									1
								)
							if freqid == 1051 or freqid == 1050 or freqid == 19525 :
								dataDate = prog_date
						else:
							raise Exception('Unsupported freq: %s', freq)

					LOGGER.info('Processed dataDate: %s', dataDate)

					if freqid != 1051 and freqid != 1050 and freqid != 19525 and freqid != 1042 and freqid != 1041 and freqid != 19524 :
						if dataDate >= logicalDate:
							msg = 'dataDate %s is larger than or equal to logicalDate (%s). This is not allowed for data integrity reasons.' % (dataDate, logicalDate)
							raise Exception(msg)

					datasourcefreqruns_sql = '''
						INSERT INTO DATASOURCEFREQRUNS
						(ID, DIRRUNID, FREQID, DATADATE,
						 CREATEDAT, UPDATEDAT)
						VALUES
						(:1, :2, :3, to_date(:4, 'YYYY/MM/DD'), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
					'''

					adminreports_conn_autocommit.execute(datasourcefreqruns_sql, [
						freqRunId,
						dirRunId,
						freqid,
						dataDate
					])

					if freqid != 1051 and freqid != 1050 and freqid != 19525:
						if freq == 'M' and dataDate.day != 1:
							LOGGER.warn('(dataDate check) freqid %s has frequency %s but the dataDate %s is not '
										'the first day of month. Skipping this DataSourceFreq record.',
										freqid, freq, dataDate )
							updateDataSourceFreq(adminreports_conn_autocommit, 
									SKIPPED_DUE_TO_NOT_FIRST_DAY_OF_MONTH, '', freqRunId)
							continue
						
					else:
						#Check for manual runs and progressive balane special case
						if freq == 'M' and prog_date.day != 1:
							LOGGER.warn('(prog_date check) freqid %s has frequency %s but the dataDate %s is not '
										'the first day of month. Skipping this DataSourceFreq record.',
										freqid, freq, dataDate )
							updateDataSourceFreq(adminreports_conn_autocommit, 
									SKIPPED_DUE_TO_NOT_FIRST_DAY_OF_MONTH, '', freqRunId)
							continue

					if freq == 'M' and safeDay is not None and safeDay > logicalDate.day:
# We only need to compare against logicalDate.day and not against any other
# fields of logicalDate, as they are implicitly checked when dataDateEndMonth
# is compared with logicalDate.
						LOGGER.warn('freqid %s has frequency %s but the logicalDate %s has not '
									'reached the safeday (%s). Skipping this DataSourceFreq record.',
									freqid, freq, logicalDate, safeDay )
						updateDataSourceFreq(adminreports_conn_autocommit, 
								SKIPPED_DUE_TO_SAFEDAY_NOT_REACHED, '', freqRunId)
						continue

					dataDateEndMonth = None
					if freq == 'M':
						dataDateEndMonth = genlib.last_day(dataDate)
						#This is to skip monthly check for logical date when downloading progressive balance report
						if freqid != 1051 and freqid != 1050 and freqid != 19525  : 
							if dataDateEndMonth >= logicalDate:
								msg = ('dataDateEndMonth %s is larger than or equal to logicalDate. '
										'This is not allowed for data integrity reasons. '
										'Skipping this DataSourceFreq record.') % dataDateEndMonth
								LOGGER.warn(msg)
								updateDataSourceFreq(adminreports_conn_autocommit, 
										SKIP_DUE_TO_DATADATEENDMONTH_GE_TO_LOGICAL_DATE, '', freqRunId)
								continue

					hours = int(safeTime[:2])
					minutes = int(safeTime[2:4])

					retrievedPathFromDB = None

					phase_sql = '''
						select id, exitcode, phase, retrievedpath
						from datasourceruns
						where freqid = :1
						and datadate = to_date(:2, 'YYYY/MM/DD')
						and exitcode = 0
						and status <> :3
						order by 
							case phase
								when :4 then 0
								when :5 then 1
							end
					'''

					phase_row = adminreports_conn.execute(phase_sql, [
						freqid, dataDate, 'C', PHASE_SEQUENCE[1], PHASE_SEQUENCE[0]
					]).fetchone()

					phaseToRun = PHASE_SEQUENCE[0]

					if phase_row:
						if phase_row[2] == PHASE_SEQUENCE[0]:
							phaseToRun = PHASE_SEQUENCE[1]
						elif phase_row[2] == PHASE_SEQUENCE[1]:
							LOGGER.info('''
								For freqid %s and for dataDate %s the final phase
								has been completed successfully. Skipping it.
							'''.strip(), freqid, dataDate)
							updateDataSourceFreq(adminreports_conn_autocommit, 
									SKIPPED_DUE_TO_FINAL_PHASE_SUCCESSFULLY_COMPLETED, '', freqRunId)
							continue

					LOGGER.info('Deduced phaseToRun: %s', phaseToRun)

					if phaseToRun == PHASE_UPLOAD and (
							SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE
								or
							os.environ.get(MEDIATION_BILLING_TEST_OVERRIDE_SUSPEND_UPLOAD_UNTIL_DOWNLOADS_ARE_DONE) == '1'):
						checkAllDownloadsDoneQuery = '''
							 select 
							 fr.id
							 from 
							 DataSourceFreq         fr
							 join Reports       ds  on ds.id = fr.reportid
							 join Admins   so  on so.id = fr.adminid
							 left join DataSourceRuns dsr   on dsr.freqid = fr.id   
															and phase = :1 
															and dsr.datadate = to_date(
																:2, 'YYYY/MM/DD'
															)
															and dsr.status = 'S'
							 where (ds.isactive = 1 and fr.isactive = 1)                                         
							 and dsr.id    IS NULL
							 order by fr.id
						'''

						all_downloads_done_row = adminreports_conn.execute(
							checkAllDownloadsDoneQuery, [PHASE_DOWNLOAD, dataDate]
						).fetchone()

						if all_downloads_done_row:
							freqidMissing = all_downloads_done_row[0]
							LOGGER.info('''
								Skipping freqid %s because an active
								DATASOURCEFREQ records was found that has
								not been downloaded successfully for datadate %s.
								The found record has ID: %s
							'''.strip(), freqid, dataDate, freqidMissing)
							updateDataSourceFreq(adminreports_conn_autocommit,
								SKIPPED_DUE_TO_NOT_ALL_DOWNLOADS_DONE, '', freqRunId)
							continue

					### Load retrievedPath.
					if phaseToRun != PHASE_DOWNLOAD:
						retrieved_check_sql = '''
							select id, exitcode, phase, retrievedpath
							from datasourceruns
							where freqid = :1
							and datadate = to_date(:2, 'YYYY/MM/DD')
							and exitcode = 0
							and status <> :3
							and phase = :4
						'''
						retrieved_check_pars = [ freqid, dataDate, 'C', PHASE_DOWNLOAD ]
						retrieved_check_row = adminreports_conn.execute(retrieved_check_sql,
																	retrieved_check_pars).fetchone()
						retrievedPathFromDB = retrieved_check_row[3]

					if phaseToRun == PHASE_DOWNLOAD:
						# Check if we have failed due to wrong password.
						passwordCheckSql = "select pwfailure from admins where code = :1"
						password_check_row = adminreports_conn.execute(
												passwordCheckSql, [soCode]).fetchone()
						pwFailure = password_check_row[0]
						pwFailureOverride = os.environ.get('MEDIATION_BILLING_TEST_OVERRIDE_PWFAILURE')
						if pwFailureOverride:
							pwFailure = pwFailureOverride

						if pwFailure == '1':
							LOGGER.warn('''
								The ADMINS record (%s) corresponding to freqid %s
								has PWFAILURE = 1. Please correct the username
								and/or password and then clear the PWFAILURE
								flag.
							'''.strip(), soCode, freqid)
							updateDataSourceFreq(adminreports_conn_autocommit,
												SKIPPED_DUE_TO_PAST_PASSW_FAILURE, 
																		'', freqRunId)
							continue

					# Check if we have reached the max tries.

					retryCheckSql = '''
						select count(*)
						from datasourceruns
						where freqid = :1
						and datadate = to_date(:2, 'YYYY/MM/DD')
						and exitcode <> 0
						and status <> :3
						and phase = :4
					'''

					retries_already_row = adminreports_conn.execute(retryCheckSql, [
						freqid, dataDate, 'C', phaseToRun
					]).fetchone()

					triesAlready = retries_already_row[0]

					if maxTries <= triesAlready:
						LOGGER.warn('''
							For freqid: %s there have been already %s tries,
							which is equal or larger than the maximum allowed
							tries (%s). Skipping this freqid.
						'''.strip(), freqid, triesAlready, maxTries)
						updateDataSourceFreq(adminreports_conn_autocommit,
								SKIPPED_DUE_TO_MAX_TRIES_REACHED, '', freqRunId)
						continue

					# Checking whether there are running or completed
					# DataSourceRuns records for this freqid.
					run_check_sql = '''
						select id, exitcode
						from datasourceruns
						where freqid = :1
						and datadate = to_date(:2, 'YYYY/MM/DD')
						and (exitcode = 0 or exitcode is null)
						and status <> :3
						and phase = :4
					'''
					run_check_pars = [
						freqid,
						dataDate,
						'C',
						phaseToRun
					]

					run_check_row = adminreports_conn.execute(
										run_check_sql, run_check_pars).fetchone()

					if run_check_row:
						if run_check_row[1] is None:
							LOGGER.warn('''
								Skipping this DataSourceFreq record,
								as a running DataSourceRuns record
								for the same date and/or time. The record
								found has id: %s.
							'''.strip(),  run_check_row[0])
							updateDataSourceFreq(adminreports_conn_autocommit,
									SKIPPED_DUE_TO_RUNNING_ALREADY, '', freqRunId)
							continue
						elif run_check_row[1] == 0:
							LOGGER.warn('''
								Skipping this DataSourceFreq record,
								as a successful DataSourceRuns record
								for the same date and/or time. The record
								found has id: %s.
							'''.strip(),  run_check_row[0])
							updateDataSourceFreq(adminreports_conn_autocommit,
									SKIPPED_DUE_TO_SUCCESS_ALREADY, '', freqRunId)
							continue

					LOGGER.info('No successful DataSourceRuns records found. '
								'Continuing with execution.')

					dateToUseForTimeCheck = dataDateEndMonth or dataDate

					time_has_come = (
						dateToUseForTimeCheck < ( logicalDate + datetime.timedelta(-1) )
							or
						dateToUseForTimeCheck < logicalDate
							and
						(
							logicalHours > hours
								or
							logicalHours == hours and logicalMinutes >= minutes
						)
					)
					
					#This is a hack for safe day/time check for progressive balance special case.
					#We only check safetime since day is going to be equal to logical date (1st of the month)
					if freqid == 1051 or freqid == 1050 or freqid == 19525 :
						time_has_come = (logicalHours > hours or logicalHours == hours and logicalMinutes >= minutes)

					if not time_has_come:
						LOGGER.info('The required time has not come yet, '
								'halting execution of this DataSourceFreq record.')
						updateDataSourceFreq(adminreports_conn_autocommit,
										SKIPPED_DUE_TIME_NOT_YET_REACHED, '', freqRunId)
						continue
					else:
						LOGGER.info('The required time has come, '
								'continuing with execution of this DataSourceFreq record.')
						
						defs_sql = '''
							 select
							 datasourcefreq.defs
							 from datasourcefreq
							 where datasourcefreq.id = :1
						'''

						defs_pars = [freqid]

						defs_row = adminreports_conn.execute(defs_sql, defs_pars).fetchone()

						defs = defs_row[0]

						LOGGER.info('From freqid %s received defs: %s', freqid, defs)

						variables_dict = parseDefs(defs)
						variables_dict[FR_NAME] = frname

						if processesLaunched >= MAX_PROCESSES_TO_LAUNCH:
							LOGGER.warn(('We have already launched %s processes, '
										'which is larger or equal to the maximum alloed (%s). '
										'No more processes will be launched during this Director run.') %
																(processesLaunched, MAX_PROCESSES_TO_LAUNCH))
							updateDataSourceFreq(adminreports_conn_autocommit,
												SKIPPED_DUE_TO_MAX_PROCESSES_LAUNCHED_REACHED, '', freqRunId)
							continue

						LOGGER.info('Launching generateScriptCLI...')

						# Process creation.

						LOGGER.info('dsname: %s', dsname)
						LOGGER.info('frname: %s', frname)

						# Retrieve a new dsrid.

						dsrid_sql = 'select DataSourceRunsSeq.nextval from dual'

						dsrid_row = adminreports_conn.execute(dsrid_sql).fetchone()

						dataSourceRunsId = dsrid_row[0]

						LOGGER.info('dataSourceRunsId: %s', dataSourceRunsId)

						fileNameToUseForLogFiles = (frname or '') + '_' + phaseToRun + '_' + str(dataSourceRunsId)

						current_datetime = datetime.datetime.now()

						currentTimestamp = genlib.datetime_to_filename_safe(current_datetime)

						fileNameToUseForLogFiles += '_' + currentTimestamp

						LOGGER.info('currentTimestamp: %s', currentTimestamp)

						platform_string = platform.platform()
						if 'Windows' in platform_string:
							executable = ['cmd', '/c']
						elif 'Linux' in platform_string:
							executable = ['bash', '-c']
						else:
							raise Exception('Unknown platform: %s' % platform_string)

						stdoutpath = os.path.join(dataSourceRunsLogPath, fileNameToUseForLogFiles + '.out')
						stderrpath = os.path.join(dataSourceRunsLogPath, fileNameToUseForLogFiles + '.err')

						# arguments = executable + [
						# 	generateScriptCLI 
						# 	+ ' 1>' + stdoutpath + ''
						# 	+ ' 2>' + stderrpath + ''
						# ]

						# LOGGER.info('Arguments that will be used: %s', arguments)

						retrievedPathDirectory = os.path.join(retrievedPath,
																genlib.date_to_YYYY_MM_DD(dataDate),
																soCode)

						LOGGER.info('retrievedPathDirectory: %s', retrievedPathDirectory)

						if not os.path.exists(retrievedPathDirectory):
							os.makedirs(retrievedPathDirectory)

						if retrievedPathFromDB is None:
							retrievedPathForThisFile = os.path.join(
								retrievedPathDirectory,
								frname + '_DSRID_' + str(dataSourceRunsId) + '_'
								+ genlib.datetime_to_filename_safe(datetime.datetime.now()) + '.'
								+ fileSuffix
							)
						else:
							retrievedPathForThisFile = retrievedPathFromDB

						environ_to_pass = dict(os.environ)
						environ_to_pass[FREQID] = str(freqid)
						environ_to_pass[FR_NAME] = str(frname)
						environ_to_pass[USERNAME] = str(soUsername)

						passw = ''
						try:
							passw = billingutil.decrypt(soEncPassword)
						except Exception as e:
							updateDataSourceFreq(adminreports_conn_autocommit, 
										ERROR_DURING_PASSWORD_DECRYPT, '', freqRunId)
							raise

						environ_to_pass[PASSWORD] = passw
						environ_to_pass[USERNAME_URL_ENC] = urllib.quote(soUsername, '')
						environ_to_pass[PASSWORD_URL_ENC] = urllib.quote(passw, '')
						environ_to_pass[DSR_ID] = str(dataSourceRunsId)
						environ_to_pass[SOURCE_OUT] = soCode
						environ_to_pass[RETRIEVE_PATH] = retrievedPathForThisFile
						environ_to_pass[PHASE] = phaseToRun
						environ_to_pass[DATA_DATE] = genlib.date_to_YYYY_MM_DD(dataDate)
						environ_to_pass[NEXT_DATA_DATE] = genlib.date_to_YYYY_MM_DD(dataDate + datetime.timedelta(days=1))
						environ_to_pass[CURRENT_DATE] = genlib.date_to_YYYY_MM_DD(datetime.date.today())
						environ_to_pass[PROG_MONTHLY_DATE] = genlib.date_to_YYYY_MM_DD(prog_date)
						
						environ_to_pass[DATA_DATE_ONLY_NUMBERS] = genlib.date_to_YYYY_MM_DD(dataDate).replace('-', '')
						environ_to_pass[DATA_DATE_ONLY_NUMBERS_YEAR_MONTH] = genlib.date_to_YYYY_MM_DD(dataDate).replace('-', '')[:-2]
						environ_to_pass[DATA_DATE_YEAR] = str(dataDate.year)
						environ_to_pass[DATA_DATE_MONTH] = str(dataDate.month)
						environ_to_pass[DATA_DATE_DAY] = str(dataDate.day)
						environ_to_pass[DATA_DATE_PREVIOUS_MONTH_YEAR] = str(
												dataDate.year 
												if dataDate.month > 1 
												else dataDate.year - 1
						)
						environ_to_pass[DATA_DATE_PREVIOUS_MONTH_MONTH] = str((dataDate.month - 1) or 12)

						if os.environ.get(WAIT_FOR_KILL) == '1':
							environ_to_pass[WAIT_FOR_KILL] = '1'

						environ_to_pass[FREQ] = freq

						if freq == 'M':
							environ_to_pass[DATA_DATE_END_MONTH] = genlib.date_to_YYYY_MM_DD(dataDateEndMonth)

						for var_key, var_val in variables_dict.iteritems():
							environ_to_pass[var_key] = var_val

						# Done process creation.

						childprun = ChildProcessRunner()
						childprun.generateScriptCLI = generateScriptCLI
						childprun.freqid = freqid
						childprun.stdoutpath = stdoutpath
						childprun.stderrpath = stderrpath
						childprun.dataSourceRunsId = dataSourceRunsId
						childprun.retrievedPathToStore = retrievedPathForThisFile
						childprun.phase = phaseToRun
						childprun.soCode = soCode
						childprun.dataDate = dataDate
						childprun.dirRunId = dirRunId
						childprun.adminreports_conn_autocommit = adminreports_conn_autocommit
						childprun.environ_to_pass = environ_to_pass

						processSemaphore.acquire()

						updateDataSourceFreq(adminreports_conn_autocommit,
												LAUNCHED_PROCESS, str(dataSourceRunsId), freqRunId)
						thread = threading.Thread(
							target = childprun.wrapRunProcessInOwnThread,
							name = fileNameToUseForLogFiles,
						)

						launchedThreads.append(thread)

						LOGGER.info('Starting thread: %s', thread.name)

						thread.start()

						processesLaunched += 1

				except Exception as e:
					LOGGER.exception(e)
					# Go to next freqid record.


		finally:
			# Wait for all the threads to finish. This is done so that the lock
			# we acquired previously (when we ran FOR UPDATE NOWAIT on the
			# DataSourceFreq table) is cleared only once all launched
			# subprocesses have finished.

			LOGGER.info("Now joining each launched thread so that the main thread waits on all of them.")
			for thread in launchedThreads:
				LOGGER.info('Joining thread with name: %s', thread.name)
				time_join_started = time.time()
				thread.join()
				time_join_finished = time.time()
				LOGGER.info('Thread with name: %s joined. Waited %.3f seconds', thread.name, 
															time_join_finished - time_join_started)

			LOGGER.info('All threads joined')

			update_directorruns_sql = 'UPDATE DIRECTORRUNS SET FINISHEDAT = CURRENT_TIMESTAMP WHERE ID = :1'
			update_directorruns_pars = [dirRunId]
			adminreports_conn_autocommit.execute(update_directorruns_sql, update_directorruns_pars)

			if dirRunErrorCode:
				update_directorruns_sql = 'UPDATE DIRECTORRUNS SET ERRORCODE = :1 WHERE ID = :2'
				update_directorruns_pars = [dirRunErrorCode, dirRunId]
				adminreports_conn_autocommit.execute(update_directorruns_sql, update_directorruns_pars)


		# End of ranslation of the CreateNewOutputRows() function.

	LOGGER.info('End of adminreports_director.')
	
class ChildProcessRunner:
	def wrapRunProcessInOwnThread(self):
		LOGGER.info('Started wrapRunProcessInOwnThread, for freqid: %s', self.freqid)

		try:
			self.runProcessInOwnThread()
		except Exception as e:
			LOGGER.exception(e)
			raise
		finally:
			processSemaphore.release()

	def runProcessInOwnThread(self):
		with get_adminreports_conn() as thread_conn:
			datasourceRunsSql = '''
				insert into DataSourceRuns
				(id, freqid, datadate, startedat, finishedat, exitcode, errordesc,
				stdoutpath, stderrpath, status, retrievedpath, phase, pid, dirrunid)
				values 
				(:1, :2, to_date(:3, 'YYYY/MM/DD'), current_timestamp, null, null, 
					null, :9, :10, :11, :12, :13, :14, :15)
			'''

			LOGGER.info('About to insert into DATASOURCERUNS table...')

			self.adminreports_conn_autocommit.execute(
					datasourceRunsSql, [
						self.dataSourceRunsId,
						self.freqid,
						self.dataDate,

						self.stdoutpath,
						self.stderrpath,
						'R',
						self.retrievedPathToStore,
						self.phase,

						# IMPORTANT: We do not insert the process PID here, as
						# an exception will be thrown (it is not available yet
						# as the process has not been started).
						-1,
						self.dirRunId
					])

			LOGGER.info('Inserted into DATASOURCERUNS table.')

			if self.phase == PHASE_DOWNLOAD:
				LOGGER.info('Attempting to lock ADMINS record with code: %s' % self.soCode )
				lock_sql = '''
					select id, code, coalesce(pwfailure, '0') from ADMINS where code = :1 FOR UPDATE
				'''
				lock_row = thread_conn.execute(lock_sql, [self.soCode]).fetchone()

				if not lock_row:
					msg = 'No ADMINS record found for code: %s' % self.soCode
					LOGGER.error(msg)
					raise Exception(msg)

				adminCode = lock_row[1]
				pwfailure = lock_row[2]

				if pwfailure == '1':
					msg = ('The ADMINS record (%s) corresponding to freqid %s has PWFAILURE = 1. '
							'Please correct the username and/or password and then clear the PWFAILURE flag.')
					msg = msg % (adminCode, self.freqid)
					LOGGER.error(msg)
					raise Exception(msg)

				LOGGER.info('Successfully locked ADMINS record with id: %s' % self.soCode)

			with open(self.stdoutpath, 'wb') as stdoutpath_file, open(self.stderrpath, 'wb') as stderrpath_file:
				arguments = self.generateScriptCLI.split()
				LOGGER.info('arguments that will be used: %s', arguments)
				if arguments[0] == 'python':
					arguments[0] = sys.executable
				process = subprocess.Popen(arguments, env = self.environ_to_pass, 
											stdout = stdoutpath_file, stderr = stderrpath_file )

			update_datasourceruns_sql = '''
				update datasourceruns set pid = :1
				where id = :2                                    
			'''

			update_datasourceruns_pars = [process.pid, self.dataSourceRunsId]

			self.adminreports_conn_autocommit.execute(update_datasourceruns_sql, update_datasourceruns_pars)

			LOGGER.info('Updated DATASOURCERUNS table with the PID of the started process.')

			exitCode = process.wait()

			LOGGER.info('got exitCode: %s', exitCode)

			if exitCode == WRONG_USERNAME_OR_PASSWORD_EXIT_CODE:
				# Important: Use thread_conn here because the ADMINS record has
				# been locked via thread_conn so if connAutoCommit is used here
				# a deadlock will occur.
				passw_sql = 'update admins set pwfailure = 1 where code = :1'
				thread_conn.execute(passw_sql, [self.soCode])

			update_datasourceruns_sql = '''
				update datasourceruns
				set finishedat = current_timestamp, 
					exitcode = :2,
					status = :3
				where id = :4
			'''

			self.adminreports_conn_autocommit.execute(update_datasourceruns_sql, [
				exitCode,
				'S' if exitCode == 0 else 'E',
				self.dataSourceRunsId,
			])

			


if __name__ == '__main__':

	try:
		main()
	except Exception as e:
		LOGGER.exception(e)
		raise

	



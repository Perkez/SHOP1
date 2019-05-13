import os, sys, logging, argparse, string, re, csv, datetime, time, json
import billingutil, genlib
import billing.dataretr.common as dcommon

LOGGER = logging.getLogger()

MONTHS = [
	'JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'
]

INSERT_TEMPLATE = """
	INSERT INTO {table}
	({column_names})
	VALUES
	({values})
"""

WRONG_USERNAME_OR_PASSWORD_MSG_CASINO_ADMIN = 'Wrong username or password.'
WRONG_USERNAME_OR_PASSWORD_MSG_GEN_ADMIN = 'Invalid Login'
PASSWORD_EXPIRED_GENBET = 'Password is expired, please use admin screen to reset'
WRONG_CLIENT_ID_OANDA = 'client_id'
UNAUTHORIZED_ACCESS_RE = re.compile('<div.*Unauthorized access.*</div>')

VALUE_LENGTH_LIMIT_WARNING = 100

INSERT_SIZE = 30 * 1000

ORA_INVALID_NUMBER = 1722


class HMACSample:
	def generateSecurityToken(self, url, httpMethod, apiKey,
							queryParameters = None, postData = None):
		import hmac, hashlib
		timestamp = str(int(round(time.time() * 1000)))
		datastring = httpMethod + url
		if queryParameters != None:
			datastring += queryParameters
		datastring += timestamp
		if postData != None:
			datastring += postData
		token = hmac.new(apiKey.decode('hex'), msg=datastring, digestmod = hashlib.sha256).hexdigest()
		return token, timestamp


def urlretrieve(url, path_or_file_obj, data = None, cookies = None, headers = None):
	LOGGER.info('About to call retrieve with url: %s, path_or_file_obj: %s, data: %s, cookies: %s, headers: %s',
							url, path_or_file_obj, data, cookies, headers)


	CONNECT_TIMEOUT_SECONDS = 5 * 60
	READ_TIMEOUT_SECONDS = 30 * 60
	TIMEOUT = (CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS)

	t0 = time.time()

	import requests
	import requests.exceptions

	if os.environ.get('FILESYSTEM_FILE') == '1':
		root_directory = billingutil.get_conf_dict()['ADMINREPORTS_FILESYSTEM_FILE_ROOT']
		LOGGER.info('Loaded ADMINREPORTS_FILESYSTEM_FILE_ROOT: %s', root_directory)

		full_path = os.path.join(root_directory, url)
		LOGGER.info('Built full_path: %s', full_path)
		LOGGER.info('full_path exists %s', os.path.exists(full_path))

		import shutil
		method = lambda u: shutil.copyfile(full_path, path_or_file_obj)

	elif os.environ.get('AKAMAI_API') == '1':
		import json, urlparse
		from akamai.edgegrid import EdgeGridAuth
		s = requests.Session()
		auth_dict = json.loads(os.environ.get('PASSWORD'))
		s.auth = EdgeGridAuth(**auth_dict)

		if data is not None and data != '':
			method = lambda u : s.post(u, data = dict(urlparse.parse_qsl(data)), timeout = TIMEOUT, verify = False)
		else:
			method = lambda u : s.get(u, timeout = TIMEOUT, verify = False)
	elif os.environ.get('LL_API') == '1':
		import urlparse
		s = requests.Session()

		url_to_encode, query_to_encode = url.split('?')

		if data is not None and data != '':
			http_method = 'POST'
		else:
			http_method = 'GET'

		hmac_sig, timestamp = HMACSample().generateSecurityToken(
														url = url_to_encode,
														httpMethod = http_method,
														queryParameters = query_to_encode,
														postData = data or None,
														apiKey = os.environ['PASSWORD'],
		)

		method = lambda u: requests.request(http_method, u,
												data = data is not None and dict(urlparse.parse_qsl(data)) or None,
												timeout = TIMEOUT,
												verify = False,
												headers = {
													'Accept' : 'application/json',
													'Content-Type' : 'application/json',
													'X-LLNW-Security-Principal' : os.environ['USERNAME'],
													'X-LLNW-Security-Timestamp' : timestamp,
													'X-LLNW-Security-Token' : hmac_sig,
												},
												cookies = cookies,
		)
	#elif os.environ.get('USE_SFTP') == '1':

		#import paramiko

		# Paramiko client configuration
		#UseGSSAPI = True             # enable GSS-API / SSPI authentication
		#DoGSSAPIKeyExchange = True
		#SFTPPort = 22

		# get host key from etc/hosts if private key file not found for REPORT
        	#hostkeytype = None
		#hostkey = None

		#sftp_key_pass = dcommon.report_key_to_sftp_key_file_path_and_password(os.environ['REPORT_KEY'])
		#Using private key file
		#keyFile = sftp_key_pass[0]
		#keyPass = sftp_key_pass[1]

		#Paramiko requires OpenSSH, so use puttygen to convert putty (.ppk) key files to OpenSSH (.pem) and store for future use
		#if(keyFile.endswith('.ppk')):
			#arguments = ['puttygen',keyFile,'-O','private-openssh','-o',os.path.splitext(keyFile)[0]+'.pem']
			#LOGGER.info('Puttygen: Arguments that will be used: %s', arguments)
			#TODO: Take care of password-protected files
			#process = subprocess.Popen(arguments)
			#puttygenExitCode = process.wait()
			#if(puttygenExitCode == 0):
				#keyFile = os.path.splitext(keyFile)[0]+'.pem'
			#else:
				#LOGGER.error('Could not convert ppk to openssh pem needed by Paramiko.')
				#raise

		#privatekey = paramiko.RSAKey.from_private_key_file(keyFile)

		# now, connect and use paramiko Transport to negotiate SSH2 across the connection





	elif data is not None and data != '':
		import urlparse
		if os.environ.get('RAW_POST_DATA') == '1':
			data_to_post = data
		else:
			data_to_post = dict(urlparse.parse_qsl(data))
		method = lambda u: requests.post(u, data = data_to_post,
															verify = False, timeout = TIMEOUT,
															cookies = cookies,
															headers = headers)
	else:
		if os.environ.get('HTTP_DIGEST_AUTH') == '1':
			from requests.auth import HTTPDigestAuth
			method = lambda u: requests.get(u,
								auth = HTTPDigestAuth(
									os.environ['USERNAME'],
									os.environ['PASSWORD'],
								),
								verify = False,
								timeout = TIMEOUT,
								cookies = cookies,
								headers = headers)
		else:
			method = lambda u: requests.get(u, verify = False, timeout = TIMEOUT, cookies = cookies, headers = headers)

	TRIES_ALLOWED = 1
	CONNECTION_FORCIBLY_CLOSED_BY_REMOTE_HOST = 10054

	for tryi in xrange(TRIES_ALLOWED):
		try:
			response = method(url)
			break
		except requests.exceptions.ConnectionError as ce:
			tries_remaining = TRIES_ALLOWED - tryi - 1
			if tries_remaining > 0:
				LOGGER.info('Caught exception: %s. Tries remaining: %s', ce, tries_remaining)
				time.sleep(1)
			else:
				raise

	bytes_written = 0
	if hasattr(response, 'iter_content'):

		if os.environ.get('EUROLIVE_JSON') == '1':
			dict_data = response.json()
			def eurolive_json_to_csv(size):
				yield ';'.join([
					'casino',
					'total_amount',
					'player_sessions',
					'dealers',
					'game_tables',
					'physical_tables',
					'tips',
				]) + '\n'
				for row in dict_data['data']:
					yield ';'.join([
						str(row['casinoName']),
						str(row['totalAmountUsd']),
						str(row['playerSessionsCount']),
						str(row['dealersCount']),
						str(row['gameTablesCount']),
						str(row['physicalTablesCount']),
						str(row['tipsCount']),
					]) + '\n'
			response.iter_content = eurolive_json_to_csv
		
		if hasattr(path_or_file_obj, 'write'):
# path_or_file_obj is a file obj
			for chunk in response.iter_content(16000):
				path_or_file_obj.write(chunk)
				bytes_written += len(chunk)
		else:
# path_or_file_obj is a string containing the file path.
			with open(path_or_file_obj, 'wb') as out_file_obj:
				for chunk in response.iter_content(16000):
					out_file_obj.write(chunk)
					bytes_written += len(chunk)
		LOGGER.info('retrieve returned with status code %s. Needed %.3f seconds. Wrote %s bytes.',
												response.status_code, time.time() - t0, bytes_written)
		#LOGGER.info('response text = %s', str(response.text))
		#LOGGER.info('response content = %s', str(response.content))

		if response.status_code != 200:
			raise dcommon.HTTPStatusCodeException(response.status_code)


	return bytes_written

class NoHeaderOrDataException(Exception): pass

def file_len(fname):
    #with open(fname) as f:
    for i, l in enumerate(fname):
        pass
    return i + 1

def insert_csv_stats(file_, conn) :

	id_q = 'select DOWNLOADED_FILE_STATS_SEQ.nextval from dual'
	record_id = conn.prepare_and_execute(id_q).fetchone()
	
	dsr_id = int(os.environ['DSR_ID'])
	freqid  = int(os.environ['FREQID'])
	
	#data_date = datetime.datetime.strptime(os.environ['DATA_DATE'], "%Y-%m-%d").date()
	data_date = os.environ['DATA_DATE']
	fname = file_.name
	fsize = int(os.stat(file_.name).st_size)
	rcount = file_len(file_)

	q = '''
	insert into downloaded_file_stats(record_id, inserted_at, dsrid, freqid, datadate, filename, filesize_bytes, record_count)
	values (:1, current_timestamp, :2, :3, TO_DATE(:4,'YYYY-MM-DD'), :5, :6, :7)
	'''
	
	conn.prepare_and_execute(q, [record_id[0], dsr_id, freqid, data_date, fname, fsize, rcount])
	conn.commit()
	
	LOGGER.info('Inserted statistics for downloaded file: %s', fname)


def sniff_dialect(file_, skip_lines = 0):
	import csv
	file_.seek(0)
	sample = ''
	for skipi in xrange(skip_lines):
		file_.next()
	for linei in xrange(500):
		try:
			sample += file_.next()
		except StopIteration:
			break
	if sample.strip() == '':
		raise NoHeaderOrDataException()
	dialect = csv.Sniffer().sniff(sample)
	LOGGER.debug('Sniffed the following Dialect: %s', dialect.__dict__)
	file_.seek(0)
	return dialect


def check_file_for_emptiness(path):
	with open(path, 'rb') as f:
		if f.read(10) == '':
			msg = 'File %s is empty' % path
			LOGGER.error(msg)
			sys.exit(dcommon.EMPTY_FILE_RECEIVED)

def urlretrieve_wrapper(url, path, data = None, cookies = None, headers = None):
	if data is not None:
		return urlretrieve(url, path, data = data, cookies = cookies, headers = headers)
	else:
		return urlretrieve(url, path, cookies = cookies, headers = headers)

def get_report_sources():
	import tempfile, json
	with tempfile.TemporaryFile() as tf:
		number_of_bytes_to_read = urlretrieve_wrapper(os.environ.get('REPORT_SOURCES_URL'), tf)
		tf.seek(0)
		result = json.load(tf)
		assert result['status'] == 'ok'
		output_list = [ ]
		for obj in result['contents']:
			if obj['type'] == 'reportGroup':
				output_dict = { }
				output_dict['id'] = obj['id']
				output_dict['type'] = obj['type']
				output_list.append(output_dict)
		output_list.sort(key = lambda o: o['id'])
		LOGGER.info('Returning reportSources ids: %s', output_list)
		return output_list

def get_cookies(url):
	import requests
# The cookies are sent during the first response, which gives a 302 status. In
# order to get this cookie we have to disallow redirects.
	res = requests.get(url, allow_redirects = False)
	assert res.status_code == 302
	return res.cookies.get_dict()

def get_simple_cookies(url, post_data):
	import requests, urlparse
	to_send = dict(urlparse.parse_qsl(post_data))
	LOGGER.info('POST data to send in order to obtain cookie: %s', str(to_send))
	res = requests.post(url, data = to_send)
	assert res.status_code == 200
	return res.cookies.get_dict()

def retr_file_obj_to_csv_reader(retr_file_obj):
	skip_lines = int(os.environ.get('SKIP_LINES', 0))
	trailing_string_to_remove = os.environ.get('TRAILING_STRING_TO_REMOVE', None)
	if os.environ.get('AKAMAI_JSON_OUTPUT') == '1':
# Returns a csv-like output, even though the source is json.
		import json
		json_obj = json.load(retr_file_obj)
		assert json_obj['status'] == 'ok'
		contents = json_obj['contents']
		if len(contents) == 0:
			raise NoHeaderOrDataException()
		distinct_headers = set( tuple(obj.keys()) for obj in contents )
		if len(distinct_headers) != 1:
			raise Exception('Found more than one headers, even though only one is allowed: %s' % distinct_headers)
		header = list(distinct_headers)[0]
		yield header
		for obj in contents:
			to_yield = [ obj[h] for h in header ]
			yield to_yield
	elif os.environ.get('OANDA_XML_OUTPUT') == '1':
		import xml.etree.ElementTree as ET
		result_tree = ET.ElementTree()
		result_tree.parse(retr_file_obj)
		iters = [
			result_tree.findall('./EXPR'),
			result_tree.findall('./EXCH'),
			result_tree.findall('./CONVERSION/ASK'),
			result_tree.findall('./CONVERSION/BID'),
		]
		yield ['base', 'quote', 'ask', 'bid']
		for expr_el, code_el, ask_el, bid_el in zip(*iters):
			yield [expr_el.text, code_el.text, ask_el.text, bid_el.text]
	elif os.environ.get('REPORT_KEY') in ('LIMELIGHT_URLS', 'LIMELIGHT_URLS_MONTHLY'):
# Returns a csv-like output, even though the source is json.
		import json
		json_obj = json.load(retr_file_obj)

		service = json_obj.get('service')
		results = json_obj['resultItem']

		obji = -1
		for obji, obj in enumerate(results):
			if obji == 0:
				yield [
					'service',
					'url',
					'seconds',
					'requests',
					'bytes',
				]
			yield [
				json_obj['service'],
				obj['itemName'],
				obj['measures']['out'].get('seconds'),
				obj['measures']['out']['requests'],
				obj['measures']['out']['bytes'],
			]

		assert obji + 1 == json_obj['totalResultsCount']

		if obji + 1 == 0:
			raise NoHeaderOrDataException()

	elif os.environ.get('REPORT_KEY') == 'LIMELIGHT_PUB_HOSTS':
# Returns a csv-like output, even though the source is json.
		import json
		json_obj = json.load(retr_file_obj)

		service = json_obj.get('service')
		results = json_obj['results']

		for obji, obj in enumerate(results):
			if obji == 0:
				yield [
					'service',
					'pub_host',
					'in_seconds',
					'in_requests',
					'in_bytes',
					'out_seconds',
					'out_requests',
					'out_bytes',
					'total_bytes',
				]
			yield [
				json_obj['service'],
				obj['itemName'],
# The following can come up empty. For this reason we are using the get() function.
				obj['measures']['in'].get('seconds'),
				obj['measures']['in'].get('requests'),
				obj['measures']['in'].get('bytes'),
				obj['measures']['out'].get('seconds'),
				obj['measures']['out'].get('requests'),
				obj['measures']['out'].get('bytes'),
				obj['measures']['total'].get('bytes'),
			]

		assert obji + 1 == json_obj['totalResultsCount']

	else:
		dialect = sniff_dialect(retr_file_obj, skip_lines)
		csv_reader = genlib.get_csv_reader_skipping_bom(retr_file_obj, dialect = dialect,
															skip_lines = skip_lines)
		header = None
		for rowi, row in enumerate(csv_reader):
			if (trailing_string_to_remove or '') != '':
				assert row[-1].endswith(trailing_string_to_remove)
				row[-1] = row[-1][:-1]
			if rowi == 0:
				header = row
			else:
				if os.environ.get('IGNORE_REOCCURENCE_OF_HEADER') == '1' and row == header:
					continue
			yield row

if __name__ == '__main__':

	LOGGER.debug('Received sys.argv: %s', sys.argv)

	LOGGER.info('PID of this process: %s', os.getpid())

	parser = argparse.ArgumentParser(
			description = 'Download, process and save as RTI a URL for PokerAdmin or CasinoAdmin')
	args = parser.parse_args()

	FREQID = os.environ['FREQID']
	DSR_ID = os.environ['DSR_ID']
	FR_NAME = os.environ['FR_NAME']

	PHASE = os.environ['PHASE']

	if os.environ.get('WAIT_FOR_KILL') == '1':
			import time
			time.sleep(15 * 60)

	SOURCE_OUT = os.environ['SOURCE_OUT']
	LOGGER.info('Received FREQID: %s', FREQID)
	LOGGER.info('Received DSR_ID: %s', DSR_ID)
	LOGGER.info('Received FR_NAME: %s', FR_NAME)

	DATARETR_RETRIEVED_PATH = billingutil.get_conf_dict()['DATARETR_RETRIEVED_PATH']

	LOGGER.info('Received DATARETR_RETRIEVED_PATH: %s', DATARETR_RETRIEVED_PATH)

	LOGGER.info('Received PHASE: %s', PHASE)

	RETRIEVE_PATH = os.environ['RETRIEVE_PATH']
	LOGGER.info('Received RETRIEVE_PATH: %s', RETRIEVE_PATH)

	if os.environ.get('GZ') == '1':
		import gzip
		open_file = gzip.open
	else:
		open_file = open

	if PHASE == dcommon.PHASE_DOWNLOAD:
		CHUNK_SIZE = os.environ.get('CHUNK_SIZE')
		REPORT_SOURCES_CHUNK_SIZE = os.environ.get('REPORT_SOURCES_CHUNK_SIZE')

		data_date_data_date_end_month_combs = [ ]
		if CHUNK_SIZE is not None:

			CHUNK_SIZE = int(CHUNK_SIZE)

			assert CHUNK_SIZE > 0

			if 'DATA_DATE' not in os.environ or 'DATA_DATE_END_MONTH' not in os.environ:
				raise Exception('CHUNK_SIZE passed but one or both of '
									'the required env vars DATA_DATE and DATA_DATE_END_MONTH not passed')

			data_date_init = genlib.parse_date_YYYY_MM_DD(os.environ['DATA_DATE'])
			data_date_end_month_init = genlib.parse_date_YYYY_MM_DD(os.environ['DATA_DATE_END_MONTH'])

			diff_days = (data_date_end_month_init - data_date_init).days

			days_chunks = [ ]
			while True:
				days_chunks.append(CHUNK_SIZE)
				if sum(days_chunks) >= diff_days:
					break
			days_chunks[-1] = diff_days - sum(days_chunks[:-1])

			current_date = data_date_init
			for diffi in days_chunks:
				data_date_data_date_end_month_combs.append([
					current_date,
					current_date + datetime.timedelta(diffi) - datetime.timedelta(1)
				])
				current_date += datetime.timedelta(diffi)
			data_date_data_date_end_month_combs[-1][-1] = data_date_end_month_init


			LOGGER.info('data_date_data_date_end_month_combs: %s', data_date_data_date_end_month_combs)

			assert data_date_data_date_end_month_combs[0][0] == data_date_init
			assert data_date_data_date_end_month_combs[-1][-1] == data_date_end_month_init
			assert (data_date_data_date_end_month_combs[-1][-1]
						- data_date_data_date_end_month_combs[0][0]).days == diff_days

			for pair0, pair1 in zip(data_date_data_date_end_month_combs,
											data_date_data_date_end_month_combs[1:]):
				assert pair0[0] <= pair0[1]
				assert (pair1[0] - pair0[1]) == datetime.timedelta(1)

		if REPORT_SOURCES_CHUNK_SIZE is not None:
			# This is for akamai.
			REPORT_SOURCES_CHUNK_SIZE = int(REPORT_SOURCES_CHUNK_SIZE)
			assert REPORT_SOURCES_CHUNK_SIZE > 0
			all_report_sources = get_report_sources()


		import collections

		if CHUNK_SIZE is not None:
			to_iter_over = data_date_data_date_end_month_combs
		elif REPORT_SOURCES_CHUNK_SIZE is not None:
			range_ = range(0, len(all_report_sources), REPORT_SOURCES_CHUNK_SIZE) + [None]
			to_iter_over = zip(range_, range_[1:])
			del range_
			LOGGER.info('to_iter_over: %s', to_iter_over)
		else:
			to_iter_over = [None]

		for iter_itemi, iter_item in enumerate(to_iter_over, 1):

			LOGGER.info('iter_item: %s', iter_item)

			if iter_item is not None:
				if CHUNK_SIZE is not None:
					from_date, to_date = iter_item
					os.environ['DATA_DATE'] = genlib.date_to_YYYY_MM_DD(from_date)
					os.environ['DATA_DATE_END_MONTH'] = genlib.date_to_YYYY_MM_DD(to_date)
				elif REPORT_SOURCES_CHUNK_SIZE is not None:
					pass
				RETRIEVE_PATH = os.environ['RETRIEVE_PATH'] + '.part' + str(iter_itemi).zfill(2)

			to_use_for_replacement = collections.defaultdict(str)
			to_use_for_replacement.update(os.environ)

			process_environment_func_name = os.environ.get('MEDIATION_BILLING_TEST_OVERRIDE_PROCESS_ENV')
			if process_environment_func_name:
				LOGGER.info('Got process_environment_func_name: %s', process_environment_func_name)
				genlib.load_name_from_string(process_environment_func_name)(to_use_for_replacement)

			should_use_simple_cookie = 'OBTAIN_SIMPLE_COOKIE_FROM_URL' in os.environ
			should_use_cookie_before_redirect = 'OBTAIN_COOKIE_FROM_URL' in os.environ

			url_to_use = string.Formatter().vformat(os.environ['URL'], [ ], to_use_for_replacement)
			post_data_from_env = os.environ.get('POST_DATA', '')

			cookies_to_send = None
			if should_use_cookie_before_redirect:
				cookie_url_to_use = string.Formatter().vformat(os.environ['OBTAIN_COOKIE_FROM_URL'], [ ], to_use_for_replacement)
				LOGGER.info('Will use cookie URL: %s', cookie_url_to_use)
				cookies_to_send = get_cookies(cookie_url_to_use)
			elif should_use_simple_cookie:
				cookie_url_to_use = string.Formatter().vformat(os.environ['OBTAIN_SIMPLE_COOKIE_FROM_URL'], [ ], to_use_for_replacement)
				cookie_post_data = string.Formatter().vformat(os.environ['OBTAIN_SIMPLE_COOKIE_POST_DATA'], [ ], to_use_for_replacement)
				LOGGER.info('Will use simple cookie URL: %s', cookie_url_to_use)
				LOGGER.info('Will use simple cookie post_data: %s', cookie_post_data)
				cookies_to_send = get_simple_cookies(cookie_url_to_use, cookie_post_data)
			
			if cookies_to_send:
				LOGGER.info('Will send cookies: %s', str(cookies_to_send))

			TO_REPLACE = '{REPORT_SOURCES_JSON_FILTER}'

			post_data_processed = post_data_from_env
			if TO_REPLACE in post_data_processed:
				import urllib, json
				post_data_processed = post_data_processed.replace(TO_REPLACE,
												 urllib.quote_plus(json.dumps(
													all_report_sources[iter_item[0] : iter_item[1]]))
				)

			post_data_to_use = string.Formatter().vformat(post_data_processed, [ ], to_use_for_replacement)

			headers_to_use = None
			if 'EXTRA_HEADERS' in os.environ:
				import json
				headers_to_use = json.loads(os.environ['EXTRA_HEADERS'])

			LOGGER.info('URL after replacement: %s', url_to_use)
			LOGGER.info('POST_DATA after replacement: %s', post_data_to_use)
			LOGGER.info('headers_to_use: %s', str(headers_to_use))

			try:
				urlretrieve_override = os.environ.get('MEDIATION_BILLING_TEST_OVERRIDE_URLRETRIEVE')
				if not urlretrieve_override:
					urlretrieve_to_use = urlretrieve_wrapper
				else:
					LOGGER.info('Received override: urlretrieve_override')
					urlretrieve_to_use = genlib.load_name_from_string(urlretrieve_override)
				if post_data_to_use == '':
					LOGGER.info('Calling urlretrieve_wrapper for GET request.')
					urlretrieve_to_use(url_to_use, RETRIEVE_PATH, cookies = cookies_to_send, headers = headers_to_use)
				else:
					LOGGER.info('Calling urlretrieve_wrapper for POST request.')
					urlretrieve_to_use(url_to_use, RETRIEVE_PATH, data = post_data_to_use, cookies = cookies_to_send, headers = headers_to_use)
			except dcommon.HTTPStatusCodeException as http_status_code_error:
				if http_status_code_error.status_code in dcommon.FORBIDDEN_HTTP_STATUS_CODES:
					sys.exit(dcommon.WRONG_USERNAME_OR_PASSWORD_EXIT_CODE)
				else:
					raise

			check_file_for_emptiness(RETRIEVE_PATH)

			after_download_check_fn_name = os.environ.get('AFTER_DOWNLOAD_CHECK_FN')
			if after_download_check_fn_name is not None:
				LOGGER.info('Found after_download_check_fn_name: %s', after_download_check_fn_name)
				after_download_check_fn = genlib.load_name_from_string(after_download_check_fn_name)
				LOGGER.info('Successfully loaded function %s', after_download_check_fn)
				with open_file(RETRIEVE_PATH, 'rb') as retr_file:
					after_download_check_fn(retr_file_obj_to_csv_reader(retr_file))
				LOGGER.info('Successfully ran function %s', after_download_check_fn)

			with open_file(RETRIEVE_PATH, 'rb') as retr_file:
				chunk_to_check_for_wrong_user_pass = retr_file.read(100)
				if (WRONG_USERNAME_OR_PASSWORD_MSG_CASINO_ADMIN in chunk_to_check_for_wrong_user_pass
						or
						WRONG_USERNAME_OR_PASSWORD_MSG_GEN_ADMIN in chunk_to_check_for_wrong_user_pass
						or
						PASSWORD_EXPIRED_GENBET in chunk_to_check_for_wrong_user_pass
						or
						WRONG_CLIENT_ID_OANDA in chunk_to_check_for_wrong_user_pass):
														sys.exit(dcommon.WRONG_USERNAME_OR_PASSWORD_EXIT_CODE)
# This will throw exception when a file is obviously not a CSV:
				if os.environ.get('SKIP_NOT_CSV_FILE_CHECK') != '1':
					def throw_not_a_csv_file():
						LOGGER.fatal('Retrieved file %s is probably not a csv file.', RETRIEVE_PATH)
						sys.exit(dcommon.NOT_A_CSV_FILE)

					retr_file.seek(0)
					if '<html>' in retr_file.read(20):
						throw_not_a_csv_file()
					retr_file.seek(0)

					try:
						dialect = sniff_dialect(retr_file)
						from dbutil.connections import get_adminreports_conn
						with get_adminreports_conn() as adminreports_conn:
							insert_csv_stats(retr_file, adminreports_conn)
					except csv.Error as e:
						throw_not_a_csv_file()


	elif PHASE == dcommon.PHASE_UPLOAD:
		insert_sql = None

		mapping_file_name = dcommon.report_key_to_mapping_file_path(os.environ['REPORT_KEY'])

		import xml.etree.ElementTree as ET
		dataretr_tree = ET.parse(mapping_file_name)
		report_element = dataretr_tree.find("./report[@key='" + os.environ['REPORT_KEY'] + "']")
		if report_element is not None:
			LOGGER.info('Found matching report element in file: %s', mapping_file_name)
		else:
			raise Exception('Could not find matching "report" element in file: %s' % mapping_file_name)

		OUTPUT_TABLE = report_element.find("./tableto").attrib['name']
		OUTPUT_PK = report_element.find("./tableto").attrib['pk']
		OUTPUT_PK_SEQUENCE = report_element.find("./tableto").attrib['sequence']

		assert (OUTPUT_TABLE.replace('_', '').isalnum())
		assert (OUTPUT_PK.replace('_', '').isalnum())
		assert (OUTPUT_PK_SEQUENCE.replace('_', '').isalnum())

		LOGGER.info('OUTPUT_TABLE: %s', OUTPUT_TABLE)

		DATA_DATE_COL = 'REPORT_DATE'
		assert DATA_DATE_COL is None or (DATA_DATE_COL.replace('_', '').isalnum())

		DATA_MONTH_COL = report_element.find("./tableto").attrib.get('datamonthcol')
		assert DATA_MONTH_COL is None or (DATA_MONTH_COL.replace('_', '').isalnum())

		nls_lang_to_set = '.AL32UTF8'
		if os.environ.get('FILEENC') == 'WIN1252':
			nls_lang_to_set = 'AMERICAN_AMERICA.WE8MSWIN1252'
		os.environ['NLS_LANG'] = nls_lang_to_set
		from dbutil.connections import get_adminreports_conn
		import glob
		with get_adminreports_conn() as adminreports_conn:
			files_to_process = glob.glob(RETRIEVE_PATH + '*')
			if len(files_to_process) == 0:
				raise Exception('Could not find RETRIEVE_PATH: %s' % RETRIEVE_PATH)

			for path_to_upload in files_to_process:
				LOGGER.info('path_to_upload: %s', path_to_upload)

				check_file_for_emptiness(path_to_upload)

				with open_file(path_to_upload, 'rb') as retrieved_file:


					skip_lines = int(os.environ.get('SKIP_LINES', 0))
					csv_reader = retr_file_obj_to_csv_reader(retrieved_file)

					csv_reader_wrapper_func_qname = os.environ.get(
								'MEDIATION_BILLING_TEST_OVERRIDE_CSV_READER_WRAPPER')

					if csv_reader_wrapper_func_qname:
						LOGGER.info('Got csv_reader_wrapper_func_qname: %s', csv_reader_wrapper_func_qname)
						csv_reader = genlib.load_name_from_string(
									csv_reader_wrapper_func_qname)(csv_reader)

					try:
						header = csv_reader.next()
					except NoHeaderOrDataException as exc:
						LOGGER.info('Caught NoHeaderOrDataException: %s', exc)
						if os.environ.get('IGNORE_LACK_OF_HEADER') == '1':
							LOGGER.info('Ignoring file that lacks header and data '
														'(after %s lines were skipped)',
																				skip_lines)
							continue
						else:
							raise

					LOGGER.debug('Found header: %s', header)
					pid = os.getpid()
					parameters_list = [ ]
					csv_header_to_mapping_element = { }
					found_rows = False
					issued_warning_for_unmapped_columns = set()
					for rowi, row in enumerate(csv_reader, 1):

						if os.environ.get('SKIP_EMPTY_LINES') == '1':
							if len(row) == 0:
								continue

						if os.environ.get('SKIP_LINES_WITH_FIRST_ELEMENT') is not None:
							if row[0] == os.environ.get('SKIP_LINES_WITH_FIRST_ELEMENT'):
								continue

						if os.environ.get('STOP_WHEN_LINE_ENCOUNTERED') is not None:
							if row[0] == os.environ.get('STOP_WHEN_LINE_ENCOUNTERED'):
								break


						found_rows = True

						column_names = [ ]
						values = [ ]
						parameters = [ ]

						column_names.append(OUTPUT_PK)
						values.append('%s.nextval' % OUTPUT_PK_SEQUENCE)

						column_names.append('REC_CRE_DATETIME')
						values.append('CURRENT_TIMESTAMP')

						placeholder_index = 1

						column_names.append('ADMIN_SOURCE_NAME')
						values.append(':' + str(placeholder_index))
						placeholder_index += 1
						parameters.append(SOURCE_OUT)

						column_names.append('REC_CRE_BY_PROC_ID')
						values.append(':' + str(placeholder_index))
						placeholder_index += 1
						parameters.append(DSR_ID)

						if DATA_DATE_COL is not None:
							column_names.append(DATA_DATE_COL)
							values.append("TO_DATE(:%s, 'YYYY-MM-DD')" % str(placeholder_index))
							placeholder_index += 1
							parameters.append(os.environ['DATA_DATE'])

						if DATA_MONTH_COL is not None:
							column_names.append(DATA_MONTH_COL)
							values.append(':' + str(placeholder_index))
							placeholder_index += 1
							parameters.append(
								os.environ['DATA_DATE'][:4] +
								"-" +
								os.environ['DATA_DATE'][5:7]
							)


						row_dict = dict(zip(header, row))

						from_keys = [el.attrib['from'] for el in report_element.findall("./mapping")]
						for csv_header, csv_value in row_dict.iteritems():

							if len(str(csv_value)) > VALUE_LENGTH_LIMIT_WARNING:
								LOGGER.warning('%s In file %s line %s: Value for column %s has length more than %s bytes.',
													dcommon.WARNING_CODE_LONG_VALUE, path_to_upload, rowi, csv_header,
														VALUE_LENGTH_LIMIT_WARNING)


							if csv_header not in csv_header_to_mapping_element:
								LOGGER.debug('Searching for mapping element with "from" : %s', csv_header)
								mapping_element = None
								for mapping_element_cand in report_element.findall("./mapping"):
									if mapping_element_cand.attrib['from'] == csv_header:
										mapping_element = mapping_element_cand
										break
								csv_header_to_mapping_element[csv_header] = mapping_element
							mapping_element = csv_header_to_mapping_element.get(csv_header)
							if mapping_element is None:
								if csv_header not in issued_warning_for_unmapped_columns:
									msg = ('%s Could not find mapping_element for csv_header: %s'
												% (dcommon.WARNING_UNMAPPED_COLUMN, csv_header))
									LOGGER.warning(msg)
									issued_warning_for_unmapped_columns.add(csv_header)
								continue
							if csv_header in from_keys:
								from_keys.pop(from_keys.index(csv_header))
							is_date = False
							remove_char = None
							if 'format' in mapping_element.attrib:
								format_ = mapping_element.attrib['format']
								if format_ == 'YYYY-MM-DD HH24:MI:SS' or format_ == 'YYYY-MM-DD HH24:MI' \
																or format_ == 'DD-MON-YY HH12.MI.SS.FF6 AM' \
																or format_ == 'DD-MON-YY HH12.MI.SS.FF6 PM' \
																or format_ == 'DD-MON-YY HH24.MI.SS.FF6' \
																or format_ == 'DD-MON-YY HH24.MI.SS.FF6 AM' \
																or format_ == 'DD-MON-YY HH24.MI.SS.FF6 PM' \
																or format_ == 'DD/MM/YYYY' \
																or format_ == 'YYYYMMDD' \
																or format_ == 'YYYY-MM-DD' \
																or format_ == 'DD-MM-YYYY' \
																or format_ == 'MM/DD/YYYY' :
									try:
										assert (
											csv_value == ''
												or
											re.compile(r'^\d{4}-\d{2}-\d{2}$').match(csv_value)
												or
											re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}$').match(csv_value)
												or
											re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$').match(csv_value)
												or
											re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$').match(csv_value)
												or
											re.compile(r'^\d{2}-[A-Z]{3}-\d{2} \d{2}.\d{2}.\d{2}.\d{6} (AM|PM)$').match(csv_value)
												or
											re.compile(r'^\d{2}-[A-Z]{3}-\d{2} \d{2}.\d{2}.\d{2}.\d{6}').match(csv_value)
												or
											re.compile(r'^\d{4}\d{2}\d{2}$').match(csv_value)
												or
											re.compile(r'^\d{4}-\d{2}-\d{2}$').match(csv_value)
												or
											re.compile(r'^\d{2}/\d{2}/\d{4}$').match(csv_value)
												or
											re.compile(r'^\d{2}-\d{2}-\d{4}$').match(csv_value)
										)
									except AssertionError:
										raise Exception('%s The date string (%s) failed format check'
												% (dcommon.ERROR_CODE_DATE_STRING_FAILED_FORMAT_CHECK,
													csv_value))
									is_date = True
							if 'thousandsep' in mapping_element.attrib:
								thousandsep = mapping_element.attrib.get('thousandsep')
								assert thousandsep in [',']
								re_to_match = re.compile(r'^[-0-9.%s]+$' % thousandsep)
								mo = re_to_match.match(csv_value)
								if mo:
									remove_char = thousandsep
								else:
									raise Exception(csv_value)
							elif 'removechar' in mapping_element.attrib:
								removechar = mapping_element.attrib.get('removechar')
								remove_char = removechar
							column_name_to_append = mapping_element.attrib.get('to', csv_header)
							assert column_name_to_append.replace('_', '').isalnum()
							column_names.append(column_name_to_append)
							if not is_date:
								values.append(':' + str(placeholder_index))
							else:
								values.append("%s(%s, '%s')"
													%
													(('TO_DATE' if 'FF' not in format_ else 'TO_TIMESTAMP'),
																		':' + str(placeholder_index), format_))
							placeholder_index += 1
							if remove_char is not None:
								csv_value_replaced = csv_value
								for remove_char_single in remove_char:
									csv_value_replaced = csv_value_replaced.replace(remove_char_single, '')
								parameters.append(csv_value_replaced)
							else:
								parameters.append(csv_value)
						if len(from_keys) > 0:
							msg = (('%s The following names: %s have <mapping> elements but no corresponding header '
									'was found in the file: %s') % (dcommon.ERROR_CODE_COLUMN_MISSING,
												from_keys,
												path_to_upload))
							raise Exception(msg)


						parameters_list.append(parameters)

						if insert_sql is None:
							insert_sql = INSERT_TEMPLATE.format(table = OUTPUT_TABLE,
									column_names = ', '.join(column_names),
									values = ', '.join(values))

						if len(parameters_list) > INSERT_SIZE:
							adminreports_conn.executemany(insert_sql, parameters_list, convert_dates = False)
							parameters_list = [ ]

						# Done processing row.

					if found_rows:
						try:
							adminreports_conn.executemany(insert_sql, parameters_list, convert_dates = False)
						except Exception as e:
							import cx_Oracle
							if isinstance(e, cx_Oracle.DatabaseError):
								if e.args[0].code == ORA_INVALID_NUMBER:
									LOGGER.error('%s ORA_INVALID_NUMBER', dcommon.ERROR_CODE_INVALID_NUMBER)
							LOGGER.debug('parameters_list which caused exception: %s', parameters_list)
							raise
					else:
						LOGGER.info("File %s is apparently well-formed but contains no data rows.", path_to_upload)
	else:
		raise Exception('Invalid phase: %s', PHASE)





*** Settings ***
Library  REST  http://localhost:5050  proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  RoboBandit

*** Variables ***
${TARGET_NAME}  CRM_Application
${TARGET_URI}  localhost:5050

#ZAP
${ZAP_PATH}  /Applications/OWASP_ZAP.app/Contents/Java/
${APPNAME}  Flask API
${CONTEXT}  Flask_API
${REPORT_TITLE}  Flask API Test Report - ZAP
${REPORT_FORMAT}  json
${ZAP_REPORT_FILE}  flask_api.json
${REPORT_AUTHOR}  Abhay Bhargav
${SCANPOLICY}  Light
${RESULTS_DIR}  /Users/abhaybhargav/Documents/Code/Python/RoboPyPipeline/results
${SRC_DIR}  /Users/abhaybhargav/Documents/Code/Python/RoboPyPipeline/src/app

*** Test Cases ***
Run SAST on Source Code with Bandit
    run bandit against python source  ${SRC_DIR}  ${RESULTS_DIR}

Run SCA on Requirements File with Safety
    run safety against python source  ${SRC_DIR}  ${RESULTS_DIR}

Initialize ZAP
    [Tags]  zap_init
    start gui zap  ${ZAP_PATH}
    sleep  20
    zap open url  http://${TARGET_URI}

Authenticate to Web Service
    &{res}=  POST  /login  {"username": "admin", "password": "admin123"}
    Integer  response status  200
    set suite variable  ${TOKEN}  ${res.headers["Authorization"]}

Get Customer by ID
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    GET  /get/2
    Integer  response status  200

Post Fetch Customer
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /fetch/customer  { "id": 3 }
    Integer  response status  200

Search Customer by Username
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /search  { "search": "dleon" }
    Integer  response status  200

ZAP Contextualize
    [Tags]  zap_context
    ${contextid}=  zap define context  ${CONTEXT}  http://${TARGET_URI}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Active Scan
    [Tags]  zap_scan
    ${scan_id}=  zap start ascan  ${CONTEXT_ID}  http://${TARGET_URI}  ${SCANPOLICY}
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    [Tags]  zap_generate_report
    zap export report  ${RESULTS_DIR}/${ZAP_REPORT_FILE}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

ZAP Die
    [Tags]  zap_kill
    zap shutdown
    sleep  3
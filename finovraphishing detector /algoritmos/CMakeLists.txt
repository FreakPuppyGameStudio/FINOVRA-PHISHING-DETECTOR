cmake_minimum_required(VERSION 3.20)

project(finovra_phishing_detector
    VERSION 0.9.0
    DESCRIPTION "Finovra Phishing Detector: analizador de correos y URLs sospechosas"
    LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Dependencias del sistema detectadas con pkg-config.
# GTK 4.10 o superior: el cuadro de confirmación usa GtkAlertDialog.
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK4 REQUIRED IMPORTED_TARGET "gtk4>=4.10")
pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)

# Matemáticas (logaritmo para la entropía de los nombres de dominio)
find_library(MATH_LIBRARY m)

# Núcleo de análisis: no depende de GTK ni de SQLite
add_library(finovra_core STATIC
    src/url_analyzer.c
    src/email_analyzer.c
    src/risk_engine.c
    src/campaign_detector.c
    src/intel.c
    src/domain_heuristics.c
)
target_include_directories(finovra_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(finovra_core PUBLIC
    ${MATH_LIBRARY}
)
target_compile_options(finovra_core PRIVATE
    -Wall -Wextra -Wpedantic
)

# Persistencia en SQLite
add_library(finovra_db STATIC
    src/database.c
)
target_link_libraries(finovra_db PUBLIC
    finovra_core
    PkgConfig::SQLITE3
)
target_compile_options(finovra_db PRIVATE
    -Wall -Wextra -Wpedantic
)

# Aplicación GTK4
add_executable(finovra-phishing-detector
    src/main.c
    ui/ui_common.c
    ui/main_window.c
    ui/dashboard.c
    ui/url_scanner.c
    ui/email_viewer.c
    ui/methodology.c
)
target_link_libraries(finovra-phishing-detector PRIVATE
    finovra_db
    PkgConfig::GTK4
)
target_compile_options(finovra-phishing-detector PRIVATE
    -Wall -Wextra -Wpedantic
)

# Pruebas
enable_testing()

add_executable(test_url_analyzer
    tests/test_url_analyzer.c
)
target_link_libraries(test_url_analyzer PRIVATE finovra_core)
add_test(NAME url_analyzer COMMAND test_url_analyzer)

add_executable(test_email_analyzer
    tests/test_email_analyzer.c
)
target_link_libraries(test_email_analyzer PRIVATE finovra_core)
add_test(NAME email_analyzer COMMAND test_email_analyzer)

add_executable(test_risk_engine
    tests/test_risk_engine.c
)
target_link_libraries(test_risk_engine PRIVATE finovra_core)
add_test(NAME risk_engine COMMAND test_risk_engine)

add_executable(test_campaign_detector
    tests/test_campaign_detector.c
)
target_link_libraries(test_campaign_detector PRIVATE finovra_core)
add_test(NAME campaign_detector COMMAND test_campaign_detector)

add_executable(test_intel
    tests/test_intel.c
)
target_link_libraries(test_intel PRIVATE finovra_core)
add_test(NAME intel COMMAND test_intel)

add_executable(test_domain_heuristics
    tests/test_domain_heuristics.c
)
target_link_libraries(test_domain_heuristics PRIVATE finovra_core)
add_test(NAME domain_heuristics COMMAND test_domain_heuristics)

add_executable(test_database
    tests/test_database.c
)
target_link_libraries(test_database PRIVATE finovra_db)
add_test(NAME database COMMAND test_database)

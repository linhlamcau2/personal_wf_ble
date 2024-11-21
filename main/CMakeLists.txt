set(srcs "main.c"
        "board.c"
        "app_mqtt.c")
idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS  ".")

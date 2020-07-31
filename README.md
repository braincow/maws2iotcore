# maws2iotcore

Program to read in over serial connection all messages provided by Vaisala weather station. Messages need to be in certain MAWS format with known field configuration.

These messages are then relayed with MQTT protocol to Google Cloud IOT Core service for data warehousing.

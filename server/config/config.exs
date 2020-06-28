import Config

config :server,
  ip: {0, 0, 0, 0},
  port: 3020,
  keypath: "/etc/tcpserver/key.txt"

#import_config "#{Mix.env()}.exs"

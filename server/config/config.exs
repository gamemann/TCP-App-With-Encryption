import Config

config :server,
  ip: {0, 0, 0, 0},
  port: 3020

#import_config "#{Mix.env()}.exs"

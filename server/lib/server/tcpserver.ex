defmodule Server.Server do
  require Logger
  use Task

  def start_link(_opts) do
    ip = Application.get_env(:server, :ip, {0, 0, 0, 0})
    port = Application.get_env(:server, :port, 3020)

    Task.start_link(__MODULE__, :listen, [ip, port])
  end

  def listen(ip, port) do
    {:ok, listen_socket} = :gen_tcp.listen(port, [:binary, active: :once, reuseaddr: true, ip: ip])

    Logger.info "Listening on port #{port}."

    loop(listen_socket)
  end

  defp loop(listen_socket) do
    {:ok, socket} = :gen_tcp.accept(listen_socket)

    {:ok, pid} = DynamicSupervisor.start_child(Server.ClientSupervisor, {Server.Client, socket})
    :gen_tcp.controlling_process(socket, pid)

    loop(listen_socket)
  end
end

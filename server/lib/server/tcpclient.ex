defmodule Server.Client do
  require Logger
  use GenServer

  @initial_state %{state: :ident, socket: nil, counter: 1}

  def start_link(socket, opts \\ []) do
    GenServer.start_link(__MODULE__, socket, opts)
  end

  def init(socket) do
    stuff = @initial_state
    stuff = %{stuff | socket: socket}

    {:ok, stuff}
  end

  def handle_info({:tcp, socket, data}, %{counter: counter} = state) do
    IO.inspect state, label: "State"

    serve(socket, counter, data)
    :inet.setopts(socket, [active: :once])

    #IO.inspect data, label: "Incoming packet"

    {:noreply, Map.put(state, :counter, counter+1)}
  end

  def handle_info({:tcp_closed, socket}, state) do
    Logger.info "Connection closed by user."

    Process.exit(self(), :normal)
  end

  def handle_info({:tcp_error, _socket, reason}, state) do
    Logger.info "Connection closed due to an error :: #{reason}"

    Process.exit(self(), :normal)
  end

  defp serve(socket, counter, data) do
    if String.trim(to_string(data)) == String.trim("quit") do
      :gen_tcp.close(socket)
    end

    case read_key() do
      {:ok, key} ->
        # Get cipher text.
        <<ctext::binary>> = :binary.part(data, {0, byte_size(data) - 16})

        # Get the tag.
        <<tag::binary-size(16)>> = :binary.part(data, {byte_size(data), -16})

        # Create seed.
        #:crypto.rand_seed(to_string(counter))

        # Create a hash for the nonce of 12 bytes.
        #hash = :crypto.strong_rand_bytes(12)

        # Create the nonce/IV.
        #<<iv::binary-size(12)>> = :binary.part(hash, {0, 12})
        #iv = "123456789012"
        <<iv::binary-size(12)>> = <<0::96>>

        # AAD
        aad = <<>>

        # Attempt to decrypt message.
        decrypted = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, ctext, aad, tag, false)

        case decrypted do
          :error ->
            Logger.error "Error decrypting message."
            Logger.info "Key (#{byte_size(key)}) => #{Base.encode16(key)}"
            Logger.info "IV (#{byte_size(iv)}) => #{Base.encode16(iv)}"
            Logger.info "CText (#{byte_size(ctext)}) => #{Base.encode16(ctext)}"
            Logger.info "Tag (#{byte_size(tag)}) => #{Base.encode16(tag)}"
            Logger.info "Data (#{byte_size(data)}) => #{Base.encode16(data)}"

          _ ->
            Logger.info "Decrypted text => #{decrypted}"
        end

      :err ->
        Logger.error "Error getting key."
    end
  end

  defp read_line(socket) do
    case :gen_tcp.recv(socket, 0) do
      {:ok, data} ->
        {:ok, data}

      {:error, msg} ->
        if msg != :closed do
          Logger.error "Error with read_line() :: #{msg}"
        end

        :error
    end
  end

  defp write_line(line, socket) do
    case :gen_tcp.send(socket, line) do
      {:error, msg} ->
        Logger.info "Error sending packet back :: #{msg}"

      _ -> :ok
    end
  end

  defp read_key() do
    case File.read("/etc/test/key.txt") do
      {:ok, contents} ->
        {:ok, contents}

      {:error, msg} ->
        Logger.error "Error reading key file :: #{msg}"
        :err
    end
  end

  def handle_cast({:event, event_id}, state) do
    {:noreply, state}
  end
end

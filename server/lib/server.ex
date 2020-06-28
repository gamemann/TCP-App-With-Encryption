defmodule Server do
  require Logger

  def accept(port) do
    case :gen_tcp.listen(port, [:binary, active: false, reuseaddr: true]) do
      {:ok, socket} ->
        Logger.info "Listening on TCP port #{port}."
        loop_accepter(socket)

      {:error, msg} ->
        Logger.error "Error listening :: #{msg}"
    end
  end

  defp loop_accepter(socket, counter \\ 1) do
    case :gen_tcp.accept(socket) do
      {:ok, client} ->
        serve(client, counter)
        loop_accepter(socket, counter + 1)

      {:error, msg} ->
        Logger.error "Error accepting connection :: #{msg}"
    end
  end

  defp serve(socket, counter) do
    case read_line(socket) do
      {:ok, data} ->
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

        write_line(data, socket)
        serve(socket, counter + 1)

      :error ->
        :err
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
end

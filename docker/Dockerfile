# ephemera の実行用イメージ（linux/amd64）
#
# バイナリはホストでクロスコンパイルしたもの（task build の bootstrap）をコピーするだけにしている。
# RUN を持たないので、arm64 のホストでもエミュレーションなしで amd64 のイメージを作れる。
#   task build-image   # = task build && docker build --platform linux/amd64 ...
#
# distroless/static の nonroot 版には CA 証明書・tzdata・非 root ユーザー（65532）が入っている。
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY bootstrap /app/ephemera

# Default port (can be overridden via environment variable)
ENV PORT=5003
EXPOSE 5003

ENTRYPOINT ["/app/ephemera"]

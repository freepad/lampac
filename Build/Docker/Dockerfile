FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY Lampac/Lampac.csproj Lampac/
COPY Shared/Shared.csproj Shared/
COPY BaseModule/BaseModule.csproj BaseModule/
COPY Catalog/Catalog.csproj Catalog/
COPY Online/Online.csproj Online/
COPY SISI/SISI.csproj SISI/
COPY DLNA/DLNA.csproj DLNA/
COPY Tracks/Tracks.csproj Tracks/
COPY JacRed/JacRed.csproj JacRed/
COPY TorrServer/TorrServer.csproj TorrServer/

RUN dotnet restore Lampac/Lampac.csproj

COPY . .
RUN dotnet publish Lampac/Lampac.csproj -c Release -o /app/publish
RUN dotnet publish BaseModule/BaseModule.csproj -c Release -o /app/publish/module
RUN dotnet publish Catalog/Catalog.csproj -c Release -o /app/publish/module
RUN dotnet publish Online/Online.csproj -c Release -o /app/publish/module
RUN dotnet publish SISI/SISI.csproj -c Release -o /app/publish/module
RUN dotnet publish DLNA/DLNA.csproj -c Release -o /app/publish/module
RUN dotnet publish Tracks/Tracks.csproj -c Release -o /app/publish/module
RUN dotnet publish JacRed/JacRed.csproj -c Release -o /app/publish/module
RUN dotnet publish TorrServer/TorrServer.csproj -c Release -o /app/publish/module


FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS runtime
EXPOSE 9118
WORKDIR /home

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip xz-utils sed chromium xvfb libnspr4 fontconfig \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .
RUN rm -rf merchant runtimes/os* runtimes/win* runtimes/linux-arm runtimes/linux-arm64 runtimes/linux-musl-arm64 runtimes/linux-musl-x64 \
    && touch isdocker

RUN mkdir -p module && echo '[{"enable":true,"dll":"Online.dll"},{"enable":true,"dll":"SISI.dll"},{"enable":true,"initspace":"Jackett.ModInit","dll":"JacRed.dll"},{"enable":true,"dll":"DLNA.dll"},{"enable":true,"initspace":"Tracks.ModInit","dll":"Tracks.dll"},{"enable":true,"initspace":"TorrServer.ModInit","dll":"TorrServer.dll"},{"enable":true,"initspace":"Catalog.ModInit","dll":"Catalog.dll"}]' > module/manifest.json

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        TORR_ARCH="amd64"; \
        NODE_ARCH="linux-x64"; \
        FFMPEG_URL="https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz"; \
        FFMPEG_DIR="ffmpeg-master-latest-linux64-gpl"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        TORR_ARCH="arm64"; \
        NODE_ARCH="linux-arm64"; \
        FFMPEG_URL="https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linuxarm64-gpl.tar.xz"; \
        FFMPEG_DIR="ffmpeg-master-latest-linuxarm64-gpl"; \
    else \
        TORR_ARCH="arm7"; \
        NODE_ARCH="linux-arm"; \
        FFMPEG_URL=""; \
    fi && \
    mkdir -p torrserver && curl -L -k -o torrserver/TorrServer-linux "https://github.com/YouROK/TorrServer/releases/latest/download/TorrServer-linux-${TORR_ARCH}" \
    && chmod +x torrserver/TorrServer-linux && \
    mkdir -p ".playwright/node/${NODE_ARCH}" && curl -L -k -o ".playwright/node/${NODE_ARCH}/node" "https://github.com/lampac-talks/lampac/releases/download/browsers/node-${NODE_ARCH}" \
    && chmod +x ".playwright/node/${NODE_ARCH}/node" && touch ".playwright/node/${NODE_ARCH}/node.ok" && \
    if [ -n "$FFMPEG_URL" ]; then \
        mkdir -p data && curl -L -k -o ffmpeg.tar.xz "$FFMPEG_URL" \
        && tar -xf ffmpeg.tar.xz && rm -f ffmpeg.tar.xz \
        && mv "${FFMPEG_DIR}/bin/ffprobe" data/ffprobe && chmod +x data/ffprobe \
        && mv "${FFMPEG_DIR}/bin/ffmpeg" data/ffmpeg && chmod +x data/ffmpeg \
        && rm -rf "${FFMPEG_DIR}"; \
    fi

RUN echo '{"LampaWeb":{"index":"lampa-main/index.html"},"chromium":{"executablePath":"/usr/bin/chromium"}}' > init.conf

ENTRYPOINT ["dotnet", "Lampac.dll"]

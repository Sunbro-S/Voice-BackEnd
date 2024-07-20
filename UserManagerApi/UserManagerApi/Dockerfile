FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["UserManagerApi/UserManagerApi.csproj", "UserManagerApi/"]
COPY ["Services/Services.csproj", "Services/"]
COPY ["Domain/Domain.csproj", "Domain/"]
COPY ["Infrastructure/Infrastructure.csproj", "Infrastructure/"]
COPY ["RPC/RPC.csproj", "RPC/"]
RUN dotnet restore "UserManagerApi/UserManagerApi.csproj"
COPY . .
WORKDIR "/src/UserManagerApi"
RUN dotnet build "UserManagerApi.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "UserManagerApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "UserManagerApi.dll"]

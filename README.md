# PostExEnum
Herramienta hecha en PowerShell para la fase de post-explotación.

Herramienta hecha en PowerShell que se puede usar en la fase de post-explotación, llamada PostExEnum. En esencia, se ha querido desarrollar algo personal (es decir, personalizado), modular y flexible que pudiera ejecutar cada función individual que pudiera necesitar y hacerlo, idealmente por ronda de ejecución, sin ningún binario externo o instalaciones en el sistema comprometido.

Se ha dividido en módulos, lo que hace que sea muy fácil de mantener y expandir. Actualmente tiene los siguientes módulos:

  •	enum: se utiliza para enumerar información importante del sistema, usuarios, configuraciones y permisos.
  
  •	privesc: busca vectores de escalada como rutas de servicio sin comillas, configuraciones incorrectas de permisos o entre aquellos que pasan desapercibidos: privilegios activos.
  
  •	utils: contiene las funciones auxiliares que se utilizan en otros módulos.

En conclusión, PostExEnum es una herramienta portátil y escalable pensaba para seguir creciendo y adaptándose a los escenarios de reconocimiento post-exploit en entornos Windows. Está hecha para ser utilizada módulo por módulo, o en su totalidad según sea necesario, capturando toda la potencia que PowerShell aporta con llamadas nativas a la API de Windows.

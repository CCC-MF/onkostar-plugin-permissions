# Onkostar-Plugin zur Berechtigungsprüfung bei Zugriff auf Patienten- und Proceduredaten

Dieses Plugin kann in anderen Plugins zur Prüfung auf Berechtigungen zum Zugriff auf Patienten- und Proceduredaten
eingesetzt werden.

Es besteht hierbei aus zwei Teilen:

* Unterverzeichnis `api`: Hier ist eine API-Library enthalten, die die Schnittstelle der Implementierung für andere Plugins verfügbar macht.
* Unterverzeichnis `impl`: Die eigentliche Implementierung des Plugins.

Die API des Plugins muss entsprechend in anderen Plugins verfügbar sein.

## Berechtigungsprüfung

Dieses Plugin unterstützt eine Berechtigungsprüfung anhand von personenstammbasierten als auch formularbasierten Berechtigungen.

Mögliche Berechtigungsanforderungen sind sowohl für die `PermissionEvaluator`en, als auch die Annotationen:

* `PermissionType.READ`
* `PermissionType.READ_WRITE`

### Prüfung der Berechtigung mithilfe eines Permission Evaluators

Zur Prüfung der Berechtigung können die implementierten `PermissionEvaluator`en einzeln als auch gemeinsam genutzt werden:

* `PersonPoolBasedPermissionEvaluator`: Berechtigungsprüfung basierend auf dem zugehörigen Personenstamm
* `FormBasedPermissionEvaluator`: Berechtigungsprüfung basierend auf dem zugehörigen Formular
* `DelegatingDataBasedPermissionEvaluator`: Berechtigungsprüfung basierend auf allen implementierten Evaluatoren

#### Beispiel der Anwendung

Das folgende Beispiel zeigt die Nutzung des `DelegatingDataBasedPermissionEvaluator`s zur Prüfung,
ob der aufrufende Benutzer Zugriff auf die Prozedur hat und gibt nur bei vorhandener Berechtigung
den Namen des Formulars zu dieser prozedur zurück.

```java
import DNPM.security.DelegatingDataBasedPermissionEvaluator;
import de.itc.onkostar.api.IOnkostarApi;

class DemoAnalyzer implements IProcedureAnalyzer {

    private final DelegatingDataBasedPermissionEvaluator permissionEvaluator;

    private final IOnkostarApi onkostarApi;

    public DemoAnalyzer(
            DelegatingDataBasedPermissionEvaluator permissionEvaluator,
            IOnkostarApi onkostarApi
    ) {
        this.permissionEvaluator = permissionEvaluator;
        this.onkostarApi = onkostarApi;
    }

    // ... übliche Methoden für einen Analyzer

    // Beispiel: Gib Formularname zurück, wenn Prozedur mit ID existiert
    // und der aufrufende Benutzer lesenden Zugriff auf diese Prozedur hat.
    // Dabei: Zugriff auf Prozedur anhand Personenstamm und Formulartyp
    public String getFormName(Map<String, Object> input) {
        var procedureId = AnalyzerUtils.getRequiredId(input, "id");

        if (procedureId.isEmpty()) {
            return "";
        }

        var procedure = onkostarApi.getProcedure(procedureId.get());

        if (
                null != procedure
                && permissionEvaluator.hasPermission(
                        SecurityContextHolder.getContext().getAuthentication(),
                        procedure,
                        PermissionType.READ
                )
        ) {
            return procedure.getFormName();
        }

        return "";
    }

}
```

### Prüfung der Berechtigung und Absicherung von Methodenaufrufen

Zusätzlich zur Prüfung mit einem Permisison Evaluator sind, basierend auf Spring AOP, folgende Annotationen verfügbar:

* `FormSecured`: Berechtigungsprüfung wird für alle Argumente vom Typ `Procedure` anhand der Berechtigung auf das zugehörige Formular durchgeführt und erlaubt immer Zugriff auf Argumente vom Typ `Patient`
* `FormSecuredResult`: Berechtigungsprüfung wird für Rückgabewerte vom Typ `Procedure` anhand der Berechtigung auf das zugehörige Formular durchgeführt und erlaubt immer Zugriff auf Rückgabewerte vom Typ `Patient`
* `PersonPoolSecured`: Berechtigungsprüfung wird für alle Argumente vom Typ `Procedure` und `Procedure` anhand des zugehörigen Personenstamms durchgeführt.
* `PersonPoolSecuredResult`: Berechtigungsprüfung wird für Rückgabewerte vom Typ `Procedure` und `Procedure` anhand des zugehörigen Personenstamms durchgeführt.

#### Beispiel für Anwendung

Analog dazu eine Implementierung einer Service-Klasse, hier mit Spring-Annotation `@Service`.

Wird die Methode `getFormName(Procedure)` aufgerufen und der Benutzer hat keinen lesenden Zugriff auf die übergebene
Prozedur, wird eine Exception geworfen.

```java
import DNPM.security.FormSecured;
import DNPM.security.PermissionType;
import DNPM.security.PersonPoolSecured;

@Service
class DemoService {

    @FormSecured(PermissionType.READ)
    @PersonPoolSecured(PermissionType.READ)
    public String getFormName(Procedure procedure) {
        return procedure.getFormName();
    }

}
```

Der Aufruf im Analyzer kann nun wie folgt aussehen:

```java
import DNPM.security.DelegatingDataBasedPermissionEvaluator;
import DNPM.security.IllegalSecuredObjectAccessException;
import de.itc.onkostar.api.IOnkostarApi;

class DemoAnalyzer implements IProcedureAnalyzer {

    private final DemoService service;

    public DemoAnalyzer(
            DemoService demoService
    ) {
        this.demoService = demoService;
    }

    // ... übliche Methoden für einen Analyzer

    // Beispiel: Gib Formularname zurück, wenn Prozedur mit ID existiert
    // und der aufrufende Benutzer lesenden Zugriff auf diese Prozedur hat.
    // Dabei: Zugriff auf Prozedur anhand Personenstamm und Formulartyp
    public String getFormName(Map<String, Object> input) {
        var procedureId = AnalyzerUtils.getRequiredId(input, "id");

        if (procedureId.isEmpty()) {
            return "";
        }

        var procedure = onkostarApi.getProcedure(procedureId.get());

        if (null != procedure) {
            try {
                return demoService.getFormName(procedure);
            } catch (IllegalSecuredObjectAccessException e) {
                // Keine Berechtigung gegeben.
                // Durch die Annotationen wird eine berechtigungsprüfung vorgenommen,
                // schlägt diese fehl, wird eine IllegalSecuredObjectAccessException geworfen.
                // In diesem Fall wird hier eine leere Zeichenkette als Rückgabewert zurückgegeben.
                return "";
            }
        }

        return "";
    }

}
```

## Nutzung der Pluginfunktionalität in eigenen Plugins

Das Plugin **onkostar-plugin-permissions** muss in Onkostar installiert sein.
Die API-JAR dieses Plugins muss zudem für das eigene Plugin eingebunden werden:

```
<dependency>
    <groupId>de.ukw.ccc.onkostar</groupId>
    <artifactId>onkostar-plugin-permissions-api</artifactId>
    <!-- Oder spätere/neuere Version -->
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Bauen des Plugins

Für das Bauen des Plugins ist zwingend JDK in Version 11 erforderlich.
Spätere Versionen des JDK beinhalten einige Methoden nicht mehr, die von Onkostar und dort benutzten Libraries verwendet
werden.

Voraussetzung ist das Kopieren der Datei `onkostar-api-2.11.1.6.jar` (oder neuer) in das Projektverzeichnis `libs`.

**_Hinweis_**: Bei Verwendung einer neueren Version der Onkostar-API oder des ATC-Codes-Plugins
muss die Datei `pom.xml` entsprechend angepasst werden.

Danach Ausführen des Befehls:

```shell
./mvnw package
```
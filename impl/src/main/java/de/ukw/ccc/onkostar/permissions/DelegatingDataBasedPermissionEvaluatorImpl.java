/*
 * MIT License
 *
 * Copyright (c) 2024 Comprehensive Cancer Center Mainfranken
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package de.ukw.ccc.onkostar.permissions;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.List;

/**
 * PermissionEvaluator zur Gesamtprüfung der Zugriffsberechtigung.
 * Die konkrete Berechtigungsprüfung wird an die nachgelagerten PermissionEvaluatoren delegiert,
 * welche jeweils einzeln dem Zugriff zustimmen müssen.
 */
@Component
public class DelegatingDataBasedPermissionEvaluatorImpl implements DelegatingDataBasedPermissionEvaluator {

    private final List<AbstractDelegatedPermissionEvaluator> permissionEvaluators;

    public DelegatingDataBasedPermissionEvaluatorImpl(final List<AbstractDelegatedPermissionEvaluator> permissionEvaluators) {
        this.permissionEvaluators = permissionEvaluators;
    }

    /**
     * Auswertung der Zugriffsberechtigung für authentifizierten Benutzer auf Zielobjekt mit angeforderter Berechtigung.
     * Hierbei wird die Berechtigungsprüfung an alle nachgelagerten PermissionEvaluatoren delegiert.
     * Alle müssen dem Zugriff zustimmen.
     *
     * @param authentication Das Authentication Objekt
     * @param targetObject Das Zielobjekt
     * @param permissionType Die angeforderte Berechtigung
     * @return Gibt <code>true</code> zurück, wenn der Benutzer die Berechtigung hat
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetObject, Object permissionType) {
        return permissionEvaluators.stream()
                .allMatch(permissionEvaluator -> permissionEvaluator.hasPermission(authentication, targetObject, permissionType));
    }

    /**
     * Auswertung anhand der ID und des Namens des Zielobjekts.
     * Hierbei wird die Berechtigungsprüfung an alle nachgelagerten PermissionEvaluatoren delegiert.
     * Alle müssen dem Zugriff zustimmen.
     *
     * @param authentication Authentication-Object
     * @param targetId ID des Objekts
     * @param targetType Name der Zielobjektklasse
     * @param permissionType Die angeforderte Berechtigung
     * @return Gibt <code>true</code> zurück, wenn der Benutzer die Berechtigung hat
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permissionType) {
        return permissionEvaluators.stream()
                .allMatch(permissionEvaluator -> permissionEvaluator.hasPermission(authentication, targetId, targetType, permissionType));
    }
}

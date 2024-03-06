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

import de.itc.onkostar.api.Procedure;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
@Aspect
public class FormBasedSecurityAspects {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final FormBasedPermissionEvaluatorImpl permissionEvaluator;

    public FormBasedSecurityAspects(
            final FormBasedPermissionEvaluatorImpl permissionEvaluator
            ) {
        this.permissionEvaluator = permissionEvaluator;
    }

    @AfterReturning(value = "@annotation(FormSecuredResult)", returning = "procedure")
    public void afterProcedureFormBased(Procedure procedure) {
        if (
                null != procedure
                        && ! permissionEvaluator.hasPermission(SecurityContextHolder.getContext().getAuthentication(), procedure, PermissionType.READ_WRITE)
        ) {
            logger.warn("Rückgabe von Prozedur blockiert: {}", procedure.getId());
            throw new IllegalSecuredObjectAccessException();
        }
    }

    @Before(value = "@annotation(FormSecured)")
    public void beforeProcedureFormBased(JoinPoint jp) {
        Arrays.stream(jp.getArgs())
                .filter(arg -> arg instanceof Procedure)
                .forEach(procedure -> {
                    if (! permissionEvaluator.hasPermission(SecurityContextHolder.getContext().getAuthentication(), procedure, PermissionType.READ_WRITE)) {
                        logger.warn("Zugriff auf Prozedur blockiert: {}", ((Procedure)procedure).getId());
                        throw new IllegalSecuredObjectAccessException();
                    }
                });
    }
}

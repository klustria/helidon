/*
 * Copyright (c) 2019, 2022 Oracle and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.helidon.microprofile.cors;

import java.util.Optional;

import javax.annotation.Priority;
import javax.enterprise.inject.spi.CDI;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

import io.helidon.microprofile.cors.CorsSupportMp.RequestAdapterMp;
import io.helidon.microprofile.cors.CorsSupportMp.ResponseAdapterMp;
import io.helidon.webserver.cors.CrossOriginConfig;

/**
 * Class CrossOriginFilter.
 */
@Priority(Priorities.HEADER_DECORATOR)
class CrossOriginFilter implements ContainerRequestFilter, ContainerResponseFilter {

    @Context
    private ResourceInfo resourceInfo;

    private CorsCdiExtension corsCdiExtension;

    CrossOriginFilter() {
        corsCdiExtension = CDI.current().getBeanManager().getExtension(CorsCdiExtension.class);
        corsCdiExtension.recordSupplierOfCrossOriginConfigFromAnnotation(this::crossOriginConfigFromAnnotationSupplier);
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        Optional<Response> response = corsCdiExtension.corsSupportMp()
                .processRequest(new RequestAdapterMp(requestContext), new ResponseAdapterMp());
        response.ifPresent(requestContext::abortWith);
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        corsCdiExtension.corsSupportMp()
                .prepareResponse(new RequestAdapterMp(requestContext), new ResponseAdapterMp(responseContext));
    }

    Optional<CrossOriginConfig> crossOriginConfigFromAnnotationSupplier() {
        return corsCdiExtension.crossOriginConfig(resourceInfo.getResourceMethod());
    }
}

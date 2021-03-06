# Copyright 2017 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from django.conf.urls import include, url
from django.contrib import admin


urlpatterns = [
    url(r'^admin/', include(admin.site.urls)),
    url(r'^asviz/', include('asviz.urls', namespace="asviz")),
    url(r'^$', include('asviz.urls', namespace="asviz")),
    url(r'^hosttime/', 'asviz.views.hosttime'),
    url(r'^config/', 'asviz.views.config'),
    url(r'^labels/', 'asviz.views.labels'),
    url(r'^locations/', 'asviz.views.locations'),
    url(r'^geolocate/', 'asviz.views.geolocate'),
]
